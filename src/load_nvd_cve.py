import json
import gzip
import argparse
import urllib.request
import logging
import pathlib
import requests
from datetime import datetime
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
USER_AGENT = 'trivialsec.com'
BASE_URL = 'https://nvd.nist.gov'
DATAFILE_DIR = '/var/cache/trivialsec'
DATE_FMT = "%Y-%m-%dT%H:%MZ"
DEFAULT_START_YEAR = 2002

def download_gzip(url, out_file):
    try:
        with urllib.request.urlopen(url) as response:
            with gzip.GzipFile(fileobj=response) as uncompressed:
                file_content = uncompressed.read()
        with open(out_file, 'wb') as f:
            f.write(file_content)
            return True

    except Exception as e:
        logger.exception(e)

    return False

def cve_items_by_year(year :int):
    json_gz_url = f'{BASE_URL}/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz'
    json_file_path = f'{DATAFILE_DIR}/nvdcve-1.1-{year}.json'
    json_file = pathlib.Path(json_file_path)
    if not json_file.is_file():
        logger.info(json_gz_url)
        if not download_gzip(json_gz_url, json_file_path):
            logger.info(f'Failed to save {json_file_path}')
    if not json_file.is_file():
        logger.info('failed to read json file')
        return False
    data = json.loads(json_file.read_text())
    for item in data['CVE_Items']:
        yield item

def normalise_cve_item(item :dict) -> CVE:
    cve = CVE()
    cve.cve_id = item['cve']['CVE_data_meta']['ID']
    original_cve = CVE()
    if cve.hydrate():
        original_cve = cve

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
        for vec in ['E', 'RL', 'RC', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA', 'CR', 'IR', 'AR']:
            if original_vector.get(vec):
                vd[vec] = original_vector.get(vec)
        vector = CVE.dict_to_vector(vd, 3)
        cvss_version = vd.get('CVSS', '3.1')
        base_score = item['impact']['baseMetricV3']['cvssV3']['baseScore']
        exploitability_score = item['impact']['baseMetricV3']['exploitabilityScore']
        impact_score = item['impact']['baseMetricV3']['impactScore']
    elif 'baseMetricV2' in item['impact'] and 'cvssV2' in item['impact']['baseMetricV2']:
        vd = CVE.vector_to_dict(item['impact']['baseMetricV2']['cvssV2']['vectorString'], 2)
        cvss_version = vd.get('CVSS', '2.0')
        # maintain values not coming from NVD
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

    cpes = set(original_cve.cpe)
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
    for ref in original_cve.references:
        reference_urls.add(ref['url'])
    for ref in item['cve']['references']['reference_data']:
        if 'cve.mitre.org' in ref.get('url'):
            continue
        if ref.get('url') not in reference_urls:
            original_cve.references.append({
                'url': ref.get('url'),
                'name': ref.get('name'),
                'source': ref.get('refsource'),
                'tags': ','.join(ref.get('tags')),
            })
    cve.references = original_cve.references
    return cve

def process_all(start_year :int = DEFAULT_START_YEAR, not_before :datetime = datetime.utcnow()):
    year = start_year or DEFAULT_START_YEAR
    while year <= datetime.utcnow().year:
        for item in cve_items_by_year(year):
            published = datetime.strptime(item['publishedDate'], DATE_FMT)
            if published < not_before:
                continue
            cve = normalise_cve_item(item)
            if not cve.persist(extra={'_nvd': item}):
                logger.error(f'failed to save {cve.cve_id}')

        year += 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-y', '--year', help='CVE files are sorted by year, optionally specify a single year', dest='year', default=None)
    parser.add_argument('--not-before', help='ISO format datetime string to skip all CVE records published until this time', dest='not_before', default=None)
    args = parser.parse_args()
    start_year=DEFAULT_START_YEAR if args.year is None else int(args.year)
    not_before = datetime(year=start_year, month=1 , day=1)
    if args.not_before is not None:
        not_before = datetime.strptime(args.not_before, DATE_FMT)
    process_all(start_year=start_year, not_before=not_before)
