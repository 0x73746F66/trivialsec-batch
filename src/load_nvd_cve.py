import atexit
import json
import gzip
import argparse
import urllib.request
import logging
import pathlib
from urllib.error import HTTPError
from datetime import datetime, timedelta
import requests
from retry.api import retry
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
GSD_BASE_URL = 'https://raw.githubusercontent.com/cloudsecurityalliance/gsd-database/main'
USER_AGENT = 'trivialsec.com'
BASE_URL = 'https://nvd.nist.gov'
DATAFILE_DIR = '/var/cache/trivialsec'
DATE_FMT = "%Y-%m-%dT%H:%MZ"
DEFAULT_START_YEAR = 2002
REPORT = {
    'task': 'nvd-cve',
    'total': 0,
    'skipped': 0,
    'updates': 0,
    'new': 0,
    'latest': False,
    'modified': False,
}

@retry((HTTPError, EOFError), tries=5, delay=1.5, backoff=3)
def get_cve_from_nvd(feed_type, force :bool = False):
    json_gz_url = f'{BASE_URL}/feeds/json/cve/1.1/nvdcve-1.1-{feed_type}.json.gz'
    json_file_path = f'{DATAFILE_DIR}/nvdcve-1.1-{feed_type}.json'
    json_file = pathlib.Path(json_file_path)
    if force is True or not json_file.is_file():
        logger.info(json_gz_url)
        with urllib.request.urlopen(json_gz_url) as response:
            with gzip.GzipFile(fileobj=response) as uncompressed:
                file_content = uncompressed.read()
        json_file.write_text(file_content.decode())
    if not json_file.is_file():
        logger.info('failed to read json file')
        return None
    data = json.loads(json_file.read_text())
    for item in data['CVE_Items']:
        yield item

def normalise_cve_item(item :dict) -> CVE:
    cve = CVE()
    cve.cve_id = item['cve']['CVE_data_meta']['ID']
    original_cve = CVE()
    original_cve.cve_id = cve.cve_id
    if cve.hydrate():
        REPORT['updates'] += 1
        original_cve.hydrate()
    else:
        REPORT['new'] += 1

    cve.assigner = item['cve']['CVE_data_meta'].get('ASSIGNER', 'cve@mitre.org')
    description = []
    for desc in item['cve']['description']['description_data']:
        description.append(desc['value'])
    cve.description = '\n'.join(description)
    cvss_version = original_cve.cvss_version
    vector = original_cve.vector
    base_score = original_cve.base_score
    exploitability_score = original_cve.exploitability_score
    impact_score = original_cve.impact_score
    original_cvss_version = original_cve.cvss_version
    original_vector = {}
    if original_cvss_version == '2.0':
        original_vector = CVE.vector_to_dict(original_cve.vector, 2)
    if original_cvss_version in ['3.0', '3.1']:
        original_vector = CVE.vector_to_dict(original_cve.vector, 2)

    if 'baseMetricV3' in item['impact'] and 'cvssV3' in item['impact']['baseMetricV3']:
        vd = CVE.vector_to_dict(item['impact']['baseMetricV3']['cvssV3']['vectorString'], 3)
        # maintain values not coming from NVD
        if original_cvss_version in ['3.0', '3.1']:
            for vec in ['E', 'RL', 'RC', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA', 'CR', 'IR', 'AR']:
                if original_vector.get(vec):
                    vd[vec] = original_vector.get(vec)
        vector = CVE.dict_to_vector(vd, 3)
        cvss_version = vd.get('CVSS', '3.1')
        base_score = item['impact']['baseMetricV3']['cvssV3']['baseScore']
        exploitability_score = item['impact']['baseMetricV3']['exploitabilityScore']
        impact_score = item['impact']['baseMetricV3']['impactScore']
    elif original_cvss_version not in ['3.0', '3.1'] and 'baseMetricV2' in item['impact'] and 'cvssV2' in item['impact']['baseMetricV2']:
        vd = CVE.vector_to_dict(item['impact']['baseMetricV2']['cvssV2']['vectorString'], 2)
        cvss_version = vd.get('CVSS', '2.0')
        # maintain values not coming from NVD
        if original_cvss_version == '2.0':
            for vec in ['E', 'RL', 'RC', 'CDP', 'TD', 'CR', 'IR', 'AR']:
                if original_vector.get(vec):
                    vd[vec] = original_vector.get(vec)
        vector = CVE.dict_to_vector(vd, 2)
        base_score = item['impact']['baseMetricV2']['cvssV2']['baseScore']
        exploitability_score = item['impact']['baseMetricV2']['exploitabilityScore']
        impact_score = item['impact']['baseMetricV2']['impactScore']

    cve.cvss_version = cvss_version
    cve.vector = vector
    cve.base_score = base_score
    cve.exploitability_score = exploitability_score
    cve.impact_score = impact_score
    cve.published_at = datetime.fromisoformat(item['publishedDate'].replace('T', ' ').replace('Z', ''))
    cve.last_modified = datetime.fromisoformat(item['lastModifiedDate'].replace('T', ' ').replace('Z', ''))

    cpes = set(original_cve.cpe or [])
    for configuration_node in item['configurations']['nodes']:
        for cpe_match in configuration_node['cpe_match']:
            cpes.add(cpe_match.get('cpe23Uri'))
    cve.cpe = list(cpes)

    cwes = set(original_cve.cwe)
    for problemtype_data in item['cve']['problemtype']['problemtype_data']:
        for cwe_item in problemtype_data['description']:
            if not cwe_item.get('value').startswith('CWE-'):
                continue
            cwes.add(cwe_item.get('value'))
    cve.cwe = list(cwes)
    reference_urls = set()
    _, year, num_id = cve.cve_id.split('-')
    cve.references = [{
        'url': f"{GSD_BASE_URL}/{year}/{num_id[:-3]}xxx/GSD-{year}-{num_id}.json",
        'name': f'GSD-{year}-{num_id}',
        'source': 'cloudsecurityalliance/gsd-database',
        'tags': [],
    }]
    for reference in original_cve.references:
        if reference.get('url') not in reference_urls:
            reference_urls.add(reference.get('url'))
            cve.references.append(reference)

    for ref in item['cve']['references']['reference_data']:
        if 'cve.mitre.org' in ref.get('url', ''):
            continue
        if ref.get('url') not in reference_urls:
            reference_urls.add(ref.get('url'))
            cve.references.append({
                'url': ref.get('url'),
                'name': ref.get('name'),
                'source': ref.get('refsource'),
                'tags': ref.get('tags', []),
            })

    return cve

def do_modified(not_before :datetime = datetime.utcnow(), force :bool = False):
    for item in get_cve_from_nvd('modified', True):
        if item is None:
            break
        REPORT['total'] += 1
        last_modified = datetime.strptime(item['lastModifiedDate'], DATE_FMT)
        if force is False and last_modified < not_before:
            REPORT['skipped'] += 1
            continue
        cve = normalise_cve_item(item)
        extra = {'_nvd': item}
        doc = cve.get_doc()
        if doc is not None:
            extra['_xforce'] = doc.get('_source', {}).get('_xforce')
        if not cve.persist(extra=extra):
            logger.error(f'failed to save {cve.cve_id}')

def do_latest():
    for item in get_cve_from_nvd('recent', True):
        if item is None:
            break
        REPORT['total'] += 1
        cve = normalise_cve_item(item)
        extra = {'_nvd': item}
        doc = cve.get_doc()
        if doc is not None:
            extra['_xforce'] = doc.get('_source', {}).get('_xforce')
        if not cve.persist(extra=extra):
            logger.error(f'failed to save {cve.cve_id}')

def main(start_year :int = DEFAULT_START_YEAR, not_before :datetime = datetime.utcnow(), force :bool = False):
    year = start_year or DEFAULT_START_YEAR
    while year <= datetime.utcnow().year:
        for item in get_cve_from_nvd(year, force):
            if item is None:
                break
            REPORT['total'] += 1
            published = datetime.strptime(item['publishedDate'], DATE_FMT)
            if force is False and published < not_before:
                REPORT['skipped'] += 1
                continue
            cve = normalise_cve_item(item)
            extra = {'_nvd': item}
            doc = cve.get_doc()
            if doc is not None:
                extra['_xforce'] = doc.get('_source', {}).get('_xforce')
            if not cve.persist(extra=extra):
                logger.error(f'failed to save {cve.cve_id}')

        year += 1

def report():
    end = datetime.utcnow()
    epoch = datetime(1970,1,1)
    elapsed = (end-epoch).total_seconds()-(start-epoch).total_seconds()
    REPORT['start'] = str(start)
    REPORT['end'] = str(end)
    REPORT['elapsed'] = str(timedelta(seconds=elapsed))
    print(repr(REPORT))

def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('-y', '--year', help='CVE files are sorted by year, optionally specify a single year', dest='year', default=None)
    parser.add_argument('--not-before', help='ISO format datetime string to skip all CVE records published until this time', dest='not_before', default=None)
    parser.add_argument('-f', '--force-process', help='Force processing all records', dest='force', action="store_true")
    parser.add_argument('-l', '--latest', help='Process the latest feed published by NVD', dest='latest', action="store_true")
    parser.add_argument('-m', '--modified', help='Process the modified feed published by NVD', dest='modified', action="store_true")
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
    start_year=DEFAULT_START_YEAR if args.year is None else int(args.year)
    not_before = datetime(year=start_year, month=1 , day=1)
    if args.not_before is not None:
        not_before = datetime.strptime(args.not_before, DATE_FMT)
    if args.latest is True:
        do_latest()
        REPORT['latest'] = True
    else:
        main(start_year=start_year, not_before=not_before, force=args.force)
    if args.modified is True:
        do_modified(not_before, force=args.force)
        REPORT['modified'] = True

if __name__ == "__main__":
    start = datetime.utcnow()
    atexit.register(report)
    run()
