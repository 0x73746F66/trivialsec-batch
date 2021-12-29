import atexit
import json
import logging
import pathlib
import argparse
from random import randint
from time import sleep
from datetime import datetime, timedelta
import requests
from retry.api import retry
from requests.exceptions import ConnectTimeout, ReadTimeout, ConnectionError
from trivialsec.models.cve import CVE
from trivialsec.helpers.config import config


session = requests.Session()
logger = logging.getLogger(__name__)
BASE_URL = 'https://exchange.xforce.ibmcloud.com'
DATAFILE_DIR = '/var/cache/trivialsec/xforce'
DATE_FMT = "%Y-%m-%dT%H:%MZ"
DEFAULT_START_YEAR = 2002
SOURCE = 'IBM X-Force Exchange'
PROXIES = None
if config.http_proxy or config.https_proxy:
    PROXIES = {
        'http': f'http://{config.http_proxy}',
        'https': f'https://{config.https_proxy}'
    }
REPORT = {
    'task': 'xforce-vulnerabilities',
    'total': 0,
    'skipped': 0,
    'updates': 0,
    'new': 0,
}
v2_0 = {
    'E': {
        'High': 'E:H',
        'Functional': 'E:F',
        'Proof-of-Concept': 'E:POC',
        'Unproven': 'E:U',
    },
    'RL': {
        'Official Fix': 'RL:OF',
        'Temporary Fix': 'RL:TF',
        'Workaround': 'RL:W',
        'Unavailable': 'RL:U',
    },
    'RC': {
        'Unconfirmed': 'RC:UC',
        'Uncorroborated': 'RC:UR',
        'Confirmed': 'RC:C',
    }
}

def store_cve(data :dict, xforce :dict):
    REPORT['total'] += 1
    update = False
    save = False
    cve = CVE(cve_id=data['cve_id'])
    original_cve = CVE(cve_id=cve.cve_id)
    if cve.hydrate():
        update = True
        original_cve.hydrate()
    else:
        logger.warning(f'Official {cve.cve_id} missing from our Database')
        cve.assigner = 'Unknown'
        cve.description = data['description']

    if cve.title is None and data.get('title') is not None:
        cve.title = data.get('title')
        save = True
    if cve.reported_at is None and data.get('reported_at') is not None:
        cve.reported_at = data.get('reported_at')
        save = True
    if cve.base_score is None and data.get('base_score') is not None:
        cve.base_score = data.get('base_score')
        save = True
    if cve.temporal_score is None and data.get('temporal_score') is not None:
        cve.temporal_score = data.get('temporal_score')
        save = True

    reference_urls = set()
    cve.references = []
    for reference in original_cve.references:
        if reference.get('url') not in reference_urls:
            reference_urls.add(reference.get('url'))
            cve.references.append(reference)

    for reference in data['references']:
        if 'cve.mitre.org' in reference.get('url', ''):
            continue
        if reference.get('url') not in reference_urls:
            reference_urls.add(reference.get('url'))
            cve.references.append(reference)
            save = True

    remediation_sources = set()
    cve.remediation = []
    for remediation in original_cve.remediation:
        if remediation.get('source_url') not in remediation_sources:
            remediation_sources.add(remediation.get('source_url'))
            cve.remediation.append(remediation)

    for remediation in data['remediation']:
        if remediation.get('source_url') is None:
            continue
        if remediation.get('source_url') not in remediation_sources:
            remediation_sources.add(remediation.get('source_url'))
            cve.remediation.append(remediation)
            save = True

    if data['vector'] is not None and data['cvss_version'] in ['3.0', '3.1']:
        vd = CVE.vector_to_dict(data['vector'], 3)
        if original_cve.cvss_version not in ['3.0', '3.1']:
            cve.cvss_version = vd['CVSS']
            cve.vector = CVE.dict_to_vector(vd, 3)
            save = True
        else:
            original_vd = CVE.vector_to_dict(data['vector'], 3)
            cvss_updated = False
            if original_vd['E'] == 'X':
                original_vd['E'] = vd['E']
                cvss_updated = True
            if original_vd['RL'] == 'X':
                original_vd['RL'] = vd['RL']
                cvss_updated = True
            if original_vd['RC'] == 'X':
                original_vd['RC'] = vd['RC']
                cvss_updated = True
            if cvss_updated is True:
                cve.vector = CVE.dict_to_vector(original_vd, 3)
                cve.cvss_version = original_vd['CVSS']
                save = True

    if save is True:
        REPORT['new' if update is False else 'updates'] += 1
        extra = None
        doc = cve.get_doc()
        if doc is not None:
            extra = {
                '_nvd': doc.get('_source', {}).get('_nvd'),
                '_xforce': xforce
            }
        cve.persist(extra=extra)
    else:
        REPORT['skipped'] += 1

def parse_file_to_dict(filename :str):
    xforce_file = pathlib.Path(filename)
    if not xforce_file.is_file():
        logger.error(f'File not found {filename}')
        return
    raw_text = xforce_file.read_text()
    xforce_data = json.loads(raw_text)
    for cve_ref in xforce_data.get('stdcode', []):
        cve_ref = f"{cve_ref.upper().replace('CVE ', 'CVE-').replace('‑', '-').replace('–', '-')}"
        if not cve_ref.startswith('CVE-'):
            logger.warning(f'Skipping {cve_ref}')
            continue
        logger.debug(f'Normalising {cve_ref}')
        try:
            data = {
                'cve_id': cve_ref,
                'title': xforce_data['title'],
                'description': xforce_data['description'],
                'vector': None,
                'cvss_version': None,
                'references': [],
                'remediation': [],
            }

            data['base_score'] = xforce_data.get('risk_level')
            data['temporal_score'] = xforce_data.get('temporal_score')
            data['reported_at'] = xforce_data['reported'].replace('Z', '')

            for ref in xforce_data.get('references', []):
                if 'cve.mitre.org' in ref['link_target']:
                    continue
                data['references'].append({
                    'url': ref['link_target'],
                    'name': ref['link_name'],
                    'source': SOURCE,
                    'tags': ['Third Party Advisory'],
                })

            data['remediation'].append({
                'type': 'advisory',
                'source': SOURCE,
                'source_id': xforce_data['xfdbid'],
                'source_url': f"{BASE_URL}/vulnerabilities/{xforce_data['xfdbid']}",
                'affected_packages': xforce_data.get('platforms_affected', []),
                'contributors': [],
                'description': xforce_data.get('remedy', xforce_data['description']),
                'published_at':  xforce_data['reported'].replace('Z', ''),
            })
            if xforce_data.get('cvss'):
                if xforce_data['cvss']['version'] == '2.0':
                    vd = CVE.vector_to_dict(xforce_data['cvss_vector'], 2)
                    data['vector'] = CVE.dict_to_vector(vd, 2)
                    data['cvss_version'] = vd.get('CVSS', xforce_data['cvss']['version'])
                if xforce_data['cvss']['version'] in ['3.0', '3.1']:
                    vd = CVE.vector_to_dict(xforce_data['cvss_vector'], 3)
                    data['vector'] = CVE.dict_to_vector(vd, 3)
                    data['cvss_version'] = vd.get('CVSS', xforce_data['cvss']['version'])

            yield data

        except Exception as ex:
            logger.exception(ex)
            logger.error(f'cve ref {cve_ref} xfdbid {xforce_data["xfdbid"]}')

def xforce_cvss_vector(obj :dict):
    if 'cvss' not in obj:
        return None
    try:
        vector = ''
        if obj['cvss']['version'] in ['1.0', '2.0']:
            if 'access_vector' in obj['cvss']:
                vector += f"AV:{obj['cvss']['access_vector'][:1].upper()}/"
            if 'access_complexity' in obj['cvss']:
                vector += f"AC:{obj['cvss']['access_complexity'][:1].upper()}/"
            if 'authentication' in obj['cvss']:
                vector += f"Au:{obj['cvss']['authentication'][:1].upper()}/"
            if 'confidentiality_impact' in obj['cvss']:
                vector += f"C:{obj['cvss']['confidentiality_impact'][:1].upper()}/"
            if 'integrity_impact' in obj['cvss']:
                vector += f"I:{obj['cvss']['integrity_impact'][:1].upper()}/"
            if 'availability_impact' in obj['cvss']:
                vector += f"A:{obj['cvss']['availability_impact'][:1].upper()}/"
        if obj['cvss']['version'] in ['3.0', '3.1']:
            if 'access_vector' in obj['cvss']:
                vector += f"AV:{obj['cvss']['access_vector'][:1].upper()}/"
            if 'access_complexity' in obj['cvss']:
                vector += f"AC:{obj['cvss']['access_complexity'][:1].upper()}/"
            if 'privilegesrequired' in obj['cvss']:
                vector += f"PR:{obj['cvss']['privilegesrequired'][:1].upper()}/"
            if 'userinteraction' in obj['cvss']:
                vector += f"UI:{obj['cvss']['userinteraction'][:1].upper()}/"
            if 'scope' in obj['cvss']:
                vector += f"S:{obj['cvss']['scope'][:1].upper()}/"
            if 'confidentiality_impact' in obj['cvss']:
                vector += f"C:{obj['cvss']['confidentiality_impact'][:1].upper()}/"
            if 'integrity_impact' in obj['cvss']:
                vector += f"I:{obj['cvss']['integrity_impact'][:1].upper()}/"
            if 'availability_impact' in obj['cvss']:
                vector += f"A:{obj['cvss']['availability_impact'][:1].upper()}/"
            if 'exploitability' in obj:
                exploitability = obj['exploitability'][:1].upper()
                vector += 'E:X/' if exploitability not in ['U', 'P', 'F', 'H'] else f'E:{exploitability}/'
            if 'remediation_level' in obj['cvss']:
                remediation_level = obj['cvss']['remediation_level'][:1].upper()
                vector += 'RL:X/' if remediation_level not in ['O', 'T', 'W', 'U'] else f'RL:{remediation_level}/'
            if 'report_confidence' in obj:
                report_confidence = obj['report_confidence'][:1].upper()
                vector += 'RC:X' if report_confidence not in ['U', 'R', 'C'] else f'RC:{report_confidence}'
            vector = CVE.dict_to_vector(CVE.vector_to_dict(vector, 3), 3)
        if obj['cvss']['version'] == '2.0':
            if 'exploitability' in obj:
                vector += 'E:ND/' if obj['exploitability'] not in v2_0['E'] else f"{v2_0['E'][obj['exploitability']]}/"
            if 'remediation_level' in obj['cvss']:
                vector += 'RL:ND/' if obj['cvss']['remediation_level'] not in v2_0['RL'] else f"{v2_0['RL'][obj['cvss']['remediation_level']]}/"
            if 'report_confidence' in obj:
                vector += 'RC:ND' if obj['report_confidence'] not in v2_0['RC'] else f"{v2_0['RC'][obj['report_confidence']]}"
            vector = CVE.dict_to_vector(CVE.vector_to_dict(vector, 2), 2)
    except (KeyError, ValueError) as ex:
        logger.exception(ex)
        logger.error(f'vector {vector} obj {repr(obj)}')
        return None
    return vector

@retry((ConnectTimeout, ReadTimeout, ConnectionError), tries=10, delay=30, backoff=5)
def query_bulk(start :datetime, end :datetime):
    response = None
    api_url = f'{BASE_URL}/api/vulnerabilities/fulltext?q=vulnerability&startDate={start.isoformat()}Z&endDate={end.isoformat()}Z'
    logger.debug(api_url)
    resp = session.get(
        api_url,
        proxies=PROXIES,
        headers={
            'x-ui': "XFE",
            'User-Agent': config.user_agent,
            'origin': BASE_URL
        },
        timeout=10
    )
    if resp.status_code != 200:
        logger.error(f'{resp.status_code} {api_url}')
        return response

    raw = resp.text
    if raw is None or not raw:
        logger.warning(f'empty response {api_url}')

    try:
        response = json.loads(raw)
    except json.decoder.JSONDecodeError as ex:
        logger.exception(ex)
        logger.error(raw)

    return response

@retry((ConnectTimeout, ReadTimeout, ConnectionError), tries=10, delay=30, backoff=5)
def query_latest(limit :int = 200):
    response = []
    api_url = f'{BASE_URL}/api/vulnerabilities/?limit={limit}'
    resp = session.get(
        api_url,
        proxies=PROXIES,
        headers={
            'x-ui': "XFE",
            'User-Agent': config.user_agent,
            'origin': BASE_URL
        },
        timeout=10
    )
    if resp.status_code != 200:
        logger.error(f'{resp.status_code} {api_url}')
    raw = resp.text
    if raw is None or not raw:
        logger.warning(f'empty response {api_url}')

    try:
        response = json.loads(raw)
    except json.decoder.JSONDecodeError as ex:
        logger.exception(ex)
        logger.error(raw)

    return response

def do_latest(limit :int = 200):
    for item in query_latest(limit):
        original_data = {}
        datafile_path = f"{DATAFILE_DIR}-{item['xfdbid']}.json"
        xforce_file = pathlib.Path(datafile_path)
        if xforce_file.is_file():
            original_data = json.loads(xforce_file.read_text())
            original_data = {**original_data, **item}
            original_data['cvss_vector'] = xforce_cvss_vector(original_data)
            item = original_data

        item['cvss_vector'] = xforce_cvss_vector(item)
        xforce_file.write_text(json.dumps(item, default=str, sort_keys=True))
        logger.info(f'parse {datafile_path}')
        for data in parse_file_to_dict(datafile_path):
            store_cve(data, xforce=item)

def do_bulk(start :datetime, end :datetime) -> bool:
    resp = query_bulk(start, end)
    if resp is None:
        logger.error('query_bulk returned empty response')
        return False
    total_rows = int(resp.get('total_rows', 0))
    logger.debug(f'total_rows {total_rows}')
    if total_rows == 0:
        logger.warning(f'no data between {start} and {end}')
        return False
    if total_rows > 200:
        rows = []
        midday = datetime(start.year, start.month, start.day, 12)
        bulk1 = query_bulk(start, midday)
        if bulk1 is not None:
            rows += bulk1.get('rows', [])
        bulk2 = query_bulk(midday, end)
        if bulk2 is not None:
            rows += bulk2.get('rows', [])
    if total_rows <= 200:
        rows = resp.get('rows', [])
    for item in rows:
        datafile = f"{DATAFILE_DIR}-{item['xfdbid']}.json"
        original_data = {}
        xforce_file = pathlib.Path(datafile)
        if xforce_file.is_file():
            logger.debug(datafile)
            original_data = json.loads(xforce_file.read_text())
            original_data = {**original_data, **item}
            item = original_data

        item['cvss_vector'] = xforce_cvss_vector(item)
        xforce_file.write_text(json.dumps(item, default=str, sort_keys=True))
        for data in parse_file_to_dict(datafile):
            store_cve(data, xforce=item)
    return True

def main(not_before :datetime):
    now = datetime.utcnow()
    end = datetime(now.year, now.month, now.day)
    start = end - timedelta(days=1)
    while start > not_before:
        logger.warning(f'between {start} and {end}')
        do_bulk(start, end)
        end = start
        start = end - timedelta(days=1)
        sleep(randint(3,6))

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
    parser.add_argument('-y', '--since-year', help='optionally specify a year to start from', dest='since_year', default=DEFAULT_START_YEAR)
    parser.add_argument('--not-before', help='ISO format datetime string to skip all records published until this time', dest='not_before', default=None)
    parser.add_argument('-r', '--recent', help='Process the latest 1-200 max published records (default 200) change limit using "--recent-limit"', dest='process_latest', action="store_true")
    parser.add_argument('-l', '--recent-limit', help='Used with "--recent" set between 1-200 max (default 200)', dest='latest_limit', default=200)
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
    start_year=DEFAULT_START_YEAR if args.since_year is None else int(args.since_year)
    not_before = datetime(year=start_year, month=1 , day=1)
    if args.not_before is not None:
        not_before = datetime.strptime(args.not_before, DATE_FMT)
    if args.process_latest is True:
        logger.debug('do_latest')
        do_latest(limit=args.latest_limit)
    else:
        main(not_before)
