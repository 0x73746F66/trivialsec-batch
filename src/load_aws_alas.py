from xml.etree.ElementTree import Element, ElementTree
import re
import logging
import argparse
import pathlib
import requests
import pytz
from datetime import datetime
from requests.exceptions import ConnectTimeout, ReadTimeout
from retry.api import retry
from bs4 import BeautifulSoup as bs
from trivialsec.models.cve import CVE
from trivialsec.helpers.config import config


session = requests.Session()
logger = logging.getLogger(__name__)
logging.basicConfig(
    format='%(asctime)s - %(name)s - [%(levelname)s] %(message)s',
    level=logging.INFO
)
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
FEEDS = {
    f'{DATAFILE_DIR}amzl1.xml': f'{BASE_URL}alas.rss',
    f'{DATAFILE_DIR}amzl2.xml': f'{BASE_URL}AL2/alas.rss'
}

@retry((ConnectTimeout, ReadTimeout), tries=10, delay=30, backoff=5)
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
    source = 'Amazon Linux AMI Security Bulletin'
    for cve_ref in data.get('cve_refs', []):
        if cve_ref == 'CVE-PENDING':
            continue
        save = False
        cve = CVE()
        cve.cve_id = cve_ref
        original_cve = CVE()
        if cve.hydrate():
            original_cve = cve
        else:
            cve.assigner = 'Unknown'
            cve.title = data["title"]
            cve.description = f'{source}\n{data.get("issue_overview", "")}'.strip()
            cve.published_at = datetime.strptime(data['pubDate'], AMZ_DATE_FORMAT).replace(tzinfo=pytz.UTC)
            cve.last_modified = datetime.strptime(data['lastBuildDate'], AMZ_DATE_FORMAT).replace(tzinfo=pytz.UTC)
            save = True

        reference_urls = set()
        for ref in original_cve.references or []:
            reference_urls.add(ref['url'])
        remediation_sources = set()
        for remediation in original_cve.remediation or []:
            remediation_sources.add(remediation['source_url'])

        cve.references = original_cve.references or []
        if data['link'] not in reference_urls:
            cve.references.append({
                'url': data['link'],
                'name': data['vendor_id'],
                'source': source,
                'tags': data.get('affected_packages'),
            })
            save = True
        cve.remediation = original_cve.remediation or []
        if data['link'] not in remediation_sources:
            cve.remediation.append({
                'type': 'patch',
                'source': source,
                'source_id': data.get('vendor_id', data['link'].split('/')[-1]),
                'source_url': data['link'],
                'description': f"{data.get('issue_correction', '')}\n\n{data.get('new_packages', '')}".strip(),
                'published_at': datetime.strptime(data['lastBuildDate'], AMZ_DATE_FORMAT).replace(tzinfo=pytz.UTC),
            })
            save = True

        if save is True:
            extra = None
            doc = cve.get_doc()
            if doc is not None:
                extra = {'_nvd': doc.get('_source', {}).get('_nvd')}
            cve.persist(extra=extra)

def main(not_before :datetime):
    for feed_file, feed_url in FEEDS.items():
        channel = download_xml_file(feed_url, feed_file)
        if not isinstance(channel, Element):
            continue
        alas_data = parse_xml(channel)
        for data in reversed(alas_data):
            published = datetime.strptime(data['pubDate'], AMZ_DATE_FORMAT)
            if published < not_before:
                continue
            html_content = fetch_url(data['link'])
            if html_content:
                data = {**data, **html_to_dict(html_content)}
            save_alas(data)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-y', '--since-year', help='optionally specify a year to start from', dest='year', default=DEFAULT_START_YEAR)
    parser.add_argument('--not-before', help='ISO format datetime string to skip all RSS records published until this time', dest='not_before', default=None)
    args = parser.parse_args()
    not_before = datetime(year=int(args.year), month=1 , day=1)
    if args.not_before is not None:
        not_before = datetime.strptime(args.not_before, AMZ_DATE_FMT)

    main(not_before)
