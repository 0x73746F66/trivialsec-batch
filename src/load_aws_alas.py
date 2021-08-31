import atexit
import re
import logging
import argparse
import pathlib
import requests
import pytz
from xml.etree.ElementTree import Element, ElementTree
from datetime import datetime, timedelta
from requests.exceptions import ConnectTimeout, ReadTimeout, ConnectionError
from retry.api import retry
from bs4 import BeautifulSoup as bs
from elasticsearch import Elasticsearch
from trivialsec.models.cve import CVE
from trivialsec.helpers.config import config


session = requests.Session()
logger = logging.getLogger(__name__)
PROXIES = None
if config.http_proxy or config.https_proxy:
    PROXIES = {
        'http': f'http://{config.http_proxy}',
        'https': f'https://{config.https_proxy}'
    }
AMZ_DATE_FORMAT = "%a, %d %b %Y %H:%M:%S %Z"
USER_AGENT = 'trivialsec.com'
BASE_URL = 'https://alas.aws.amazon.com/'
DATAFILE_DIR = '/var/cache/trivialsec/'
ALAS_PATTERN = r"(ALAS\-\d{4}\-\d*)"
AMZ_DATE_FMT = "%Y-%m-%dT%H:%MZ"
DEFAULT_START_YEAR = 2011
DEFAULT_INDEX = 'cves'
FEEDS = {
    f'{DATAFILE_DIR}amzl1.xml': f'{BASE_URL}alas.rss',
    f'{DATAFILE_DIR}amzl2.xml': f'{BASE_URL}AL2/alas.rss'
}
REPORT = {
    'task': 'amzl-alas-rss',
    'total': 0,
    'skipped': 0,
    'updates': 0,
    'new': 0,
}

@retry((ConnectTimeout, ReadTimeout, ConnectionError), tries=10, delay=30, backoff=5)
def fetch_url(url :str):
    logger.info(url)
    resp = session.get(
        url,
        proxies=PROXIES,
        headers={
            'User-Agent': config.user_agent,
            'Referer': BASE_URL
        },
        timeout=10
    )
    if resp.status_code != 200:
        logger.info(f'{resp.status_code} {url}')
        return None
    return resp.text

def html_to_dict(html_content :str):
    result = {}
    soup = bs(html_content, 'html.parser')
    issue_correction = soup.find(id='issue_correction')
    if issue_correction is not None:
        result['issue_correction'] = issue_correction.get_text(' ', strip=True).replace('Issue Correction: ', '')
    issue_overview = soup.find(id='issue_overview')
    if issue_overview is not None:
        result['issue_overview'] = issue_overview.get_text(' ', strip=True).replace('Issue Overview: ', '')
    affected_packages = soup.find(id='affected_packages')
    if affected_packages is not None:
        result['affected_packages'] = affected_packages.get_text(' ', strip=True).replace('Affected Packages: ', '')
    new_packages = soup.find(id='new_packages')
    if new_packages is not None:
        result['new_packages'] = new_packages.pre.get_text('\n', strip=False)
    return result

def download_xml_file(url :str, local_file :str):
    raw_file = pathlib.Path(local_file)
    if not raw_file.is_file():
        raw = fetch_url(url)
        if raw is None:
            logger.info(f'Failed to save {local_file}')
            return None
        raw_file.write_text(raw)
    if not raw_file.is_file():
        logger.info('failed to read xml file')
        return None
    tree = ElementTree()
    tree.parse(local_file)
    return tree.find('.//channel')

def parse_xml(channel :Element):
    results = []
    for elem in channel:
        if elem.tag != 'item':
            continue
        data = {}
        for item in elem:
            if item.tag == 'description':
                data['cve_refs'] = list(filter(None, [x.strip() for x in item.text.split(',')]))
            else:
                data[item.tag] = item.text
        data['vendor_id'] = None
        matches = re.search(ALAS_PATTERN, data['title'])
        if matches is not None:
            data['vendor_id'] = matches.group(1)
        results.append(data)

    return results

def save_alas(data :dict):
    amz_linux_family = 2 if 'AL2/alas' in data['feed_url'] else 1
    source = f'Amazon Linux {amz_linux_family} AMI Security Bulletin'
    for cve_ref in data.get('cve_refs', []):
        REPORT['total'] += 1
        update = False
        if cve_ref == 'CVE-PENDING':
            REPORT['skipped'] += 1
            continue
        save = False
        cve = CVE()
        cve.cve_id = cve_ref
        original_cve = CVE()
        if cve.hydrate():
            update = True
            original_cve = cve
        else:
            cve.assigner = 'Unknown'
            cve.title = data["title"]
            cve.description = f'{source}\n{data.get("issue_overview", "")}'.strip()
            cve.published_at = datetime.strptime(data['pubDate'], AMZ_DATE_FORMAT).replace(tzinfo=pytz.UTC)
            cve.last_modified = datetime.strptime(data['lastBuildDate'], AMZ_DATE_FORMAT).replace(tzinfo=pytz.UTC)
            save = True


        reference_urls = set([ref['url'] for ref in original_cve.references])
        cve.references = []
        for reference in original_cve.references:
            if reference.get('url') not in reference_urls:
                cve.references.append(reference)

        if data['link'] not in reference_urls:
            reference_urls.add(data['link'])
            cve.references.append({
                'url': data['link'],
                'name': data['vendor_id'],
                'source': source,
                'tags': ['Vendor Advisory', f'AL{amz_linux_family} ALAS'],
            })
            save = True

        remediation_sources = set([source['source_url'] for source in original_cve.remediation])
        cve.remediation = []
        for remediation in original_cve.remediation:
            if remediation.get('source_url') not in remediation_sources:
                cve.remediation.append(remediation)

        if data['link'] not in remediation_sources:
            remediation_sources.add(data['link'])
            cve.remediation.append({
                'type': 'patch',
                'source': source,
                'source_id': data.get('vendor_id', data['link'].split('/')[-1]),
                'source_url': data['link'],
                'affected_packages': data.get('affected_packages', []),
                'contributors': [],
                'description': f"{data.get('issue_correction', '')}\n\n{data.get('new_packages', '')}".strip(),
                'published_at': datetime.strptime(data['lastBuildDate'], AMZ_DATE_FORMAT).replace(tzinfo=pytz.UTC),
            })
            save = True

        if save is True:
            REPORT['new' if update is False else 'updates'] += 1
            extra = None
            doc = cve.get_doc()
            if doc is not None:
                extra = {
                    '_nvd': doc.get('_source', {}).get('_nvd'),
                    '_xforce': doc.get('_source', {}).get('_xforce')
                }
            cve.persist(extra=extra)
        else:
            REPORT['skipped'] += 1

def main(not_before :datetime, force :bool = False):
    for feed_file, feed_url in FEEDS.items():
        channel = download_xml_file(feed_url, feed_file)
        if not isinstance(channel, Element):
            continue
        alas_data = parse_xml(channel)
        for data in reversed(alas_data):
            published = datetime.strptime(data['pubDate'], AMZ_DATE_FORMAT)
            if force is False and published < not_before:
                REPORT['total'] += 1
                REPORT['skipped'] += 1
                continue
            html_content = fetch_url(data['link'])
            if html_content:
                data = {**data, **html_to_dict(html_content)}
            data['feed_url'] = feed_url
            save_alas(data)

def report():
    end = datetime.utcnow()
    epoch = datetime(1970,1,1)
    elapsed = (end-epoch).total_seconds()-(start-epoch).total_seconds()
    REPORT['start'] = str(start)
    REPORT['end'] = str(end)
    REPORT['elapsed'] = str(timedelta(seconds=elapsed))
    print(repr(REPORT))

if __name__ == "__main__":
    start = datetime.utcnow()
    atexit.register(report)
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--index', help='Elasticsearch index', dest='index', default=DEFAULT_INDEX)
    parser.add_argument('-y', '--since-year', help='optionally specify a year to start from', dest='year', default=DEFAULT_START_YEAR)
    parser.add_argument('--not-before', help='ISO format datetime string to skip all RSS records published until this time', dest='not_before', default=None)
    parser.add_argument('-f', '--force-process', help='Force processing all records', dest='force', action="store_true")
    parser.add_argument('-s', '--only-show-errors', help='set logging level to ERROR (default CRITICAL)', dest='log_level_error', action="store_true")
    parser.add_argument('-q', '--quiet', help='set logging level to WARNING (default CRITICAL)', dest='log_level_warning', action="store_true")
    parser.add_argument('-v', '--verbose', help='set logging level to INFO (default CRITICAL)', dest='log_level_info', action="store_true")
    parser.add_argument('-vv', '--debug', help='set logging level to DEBUG (default CRITICAL)', dest='log_level_debug', action="store_true")
    args = parser.parse_args()
    log_level = logging.CRITICAL
    if args.log_level_error:
        log_level = logging.ERROR
    if args.log_level_warning:
        log_level = logging.WARNING
    if args.log_level_info:
        log_level = logging.INFO
    if args.log_level_debug:
        log_level = logging.DEBUG
    logging.basicConfig(
        format='%(asctime)s - %(name)s - [%(levelname)s] %(message)s',
        level=log_level
    )
    es = Elasticsearch(f"{config.elasticsearch.get('scheme')}{config.elasticsearch.get('host')}:{config.elasticsearch.get('port')}")
    es.indices.create(index=args.index, ignore=400)

    not_before = datetime(year=int(args.year), month=1 , day=1)
    if args.not_before is not None:
        not_before = datetime.strptime(args.not_before, AMZ_DATE_FMT)

    main(not_before, force=args.force)
