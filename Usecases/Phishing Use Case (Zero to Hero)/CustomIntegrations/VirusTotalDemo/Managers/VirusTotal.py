# ==============================================================================
# title           :VirusTotalManager.py
# description     :This Module contain all VirusTotal API functions.
# author          :zivh@siemplify.co
# date            :03-28-18
# python_version  :2.7
# libraries       :
# requirements    :
# product_version : v2.0
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================
import requests
import os
import copy
from datetime import datetime
from TIPCommon import SiemplifySession

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# =====================================
#             CONSTANTS               #
# =====================================
FILEHASH_TYPE = 'file'
URL_TYPE = 'url'
DUMMY_URL_FOR_TEST = 'https://www.google.co.il'

HEADERS = {"Accept-Encoding": "gzip, deflate",
           "User-Agent": "gzip,  VirusTotal Public API v2.0"}

API_ROOT = 'https://www.virustotal.com/vtapi/v2/{0}/{1}'

QUEUED_FOR_ANALYSIS = -2

FILE_ENRICHMENT_PATTERN = {
    "MD5": None,
    "SHA1": None,
    "Scan ID": None,
    "Last Scan Date": None,
    "Online Report Link": None,
    "Risk Score": None,
    "Detected Engines List": None
}

URL_ENRICHMENT_PATTERN = {
    "Scanned URL": None,
    "Scan ID": None,
    "Last Scan Date": None,
    "Online Report Link": None,
    "Risk Score": None,
    "Detected Engines List": None
}

DOMAIN_ENRICHMENT_PATTERN = {
    "Categories": None,
    "Bit Defender Category": None,
    "Bit Defender Domain Info": None,
    "Alexa Category": None,
    "Alexa Domain Info": None,
    "Forcepoint ThreatSeeker Category": None
}


ADDRESS_ENRICHMENT_PATTERN = {
    "Country": None,
    "Related Domains": None
}

ENTITY_REPORT_KEY = "Report"
ENTITY_STATUS_KEY = "Status"
ENTITY_TASK_ID_KEY = 'Task ID'

# Scan IP messages indicators.
NO_DATA_FOUND_MESSAGE = 'No Data Found'
RESOURCE_COULD_NOT_BE_FOUND_MESSAGE = 'resource could not be found'
INVALID_MESSAGE = 'Invalid'


# =====================================
#              CLASSES                #
# =====================================
class VirusTotalManagerError(Exception):
    """
    General Exception for VirusTotal manager
    """
    pass


class ScanStatus(object):
    DONE = "Done"
    MISSING = "Missing"
    QUEUED = "Queued"


class VirusTotalManager(object):
    def __init__(self, api_key, verify_ssl=False):
        self.api_key = api_key
        self.session = SiemplifySession(sensitive_data_arr=[self.api_key])
        self.session.verify = verify_ssl
        self.session.headers.update(HEADERS)

    @staticmethod
    def validate_response(response, error_msg="An error occurred"):
        try:
            response.raise_for_status()

        except requests.HTTPError as error:

            # Not a JSON - return content
            raise VirusTotalManagerError(
                "{error_msg}: {error} - {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=error.response.content)
            )

    def test_connectivity(self):
        report = self.get_url_or_file_report(DUMMY_URL_FOR_TEST, URL_TYPE)
        if report:
            return True
        return False

    def scan_url(self, resource):
        """
        Retrieve a report on a given url/file
        :param resource: {string} The file of the url,
        :return: {dict}
        """
        params = {'apikey': self.api_key, 'url': resource}
        report_url = API_ROOT.format('url', 'scan')
        response = self.session.post(report_url, params=params)
        self.validate_response(response)
        return response.json().get('scan_id') if self.check_for_error(response) else None

    def rescan_file(self, resource):
        """
        Retrieve a report on a given url/file
        :param resource: {string} The file of the url,
        :return: scan id {string}
        """
        params = {'apikey': self.api_key, 'resource': resource}
        report_url = API_ROOT.format('file', 'rescan')
        response = self.session.post(report_url, params=params)
        self.validate_response(response)
        return response.json().get('scan_id') if self.check_for_error(response) else None

    def get_url_or_file_report(self, resource, resource_type):
        """
        Retrieve a report on a given url/file
        :param resource: {string} The file of the url,
        :param resource_type: {string} indicate weather resource is url or file, can be FILEHASH_TYPE or URL_TYPE
        :return: {dict}
        """
        params = {'apikey': self.api_key, 'resource': resource}
        report_url = API_ROOT.format(resource_type, 'report')
        response = self.session.post(report_url, params=params)
        self.validate_response(response)
        return response.json() if self.check_for_error(response) else None

    def get_domain_report(self, domain):
        """
        Retrieve a report on a given domain
        :param domain: domain name
        :return: {dict} report with domain information
        """
        parameters = {'apikey': self.api_key, 'domain': domain}
        report_url = API_ROOT.format('domain', 'report')
        response = self.session.get(report_url, params=parameters)
        return response.json() if self.check_for_error(response) else None

    def get_address_report(self, ip_address):
        """
        Retrieve a report on a given ip address
        :param ip_address: {string} xx.xx.xx.xx
        :return: {dict} report with ip address information
        """
        parameters = {'apikey': self.api_key, 'ip': ip_address}
        report_url = API_ROOT.format('ip-address', 'report')
        response = self.session.get(report_url, params=parameters)
        return response.json() if self.check_for_error(response) else None

    def upload_file(self, file_path, file_byte_array=None):
        """
        The VirusTotal API allows you to send files.
        :param file_path: {string} file full path
        :param file_byte_array: {string}
        :return: {unicode} scan_id for query the report later.
        """
        # File size limit is 32MB
        file_name = os.path.basename(file_path)
        params = {'apikey': self.api_key}

        if file_byte_array:
            files = {'file': (file_name, file_byte_array)}
        else:
            files = {'file': (file_name, open(file_path, 'rb'))}

        response = self.session.post(API_ROOT.format('file', 'scan'), files=files, params=params)
        return response.json()['scan_id'] if self.check_for_error(response) else None

    def get_report_by_scan_id(self, scan_id):
        """
        specify a scan_id to access a specific report
        query the report until the result shows up.
        :param scan_id: scan_id (sha256-timestamp as returned by the file upload API)
        :return: {dict} scan report
        """
        report = self.get_url_or_file_report(scan_id, FILEHASH_TYPE)
        # response_code: If the requested item is still queued for analysis it will be -2.
        # If the item was indeed present and it could be retrieved it will be 1.
        if report['response_code'] == QUEUED_FOR_ANALYSIS:
            return None
        return report

    @staticmethod
    def check_for_error(response):
        """
        Validate response
        :param response: {requests.response} requests information
        :return: {boolean} True if scan report is valid
        """
        try:
            # response_code = 0 If the item not present in VirusTotal's dataset.
            # response_code = 1 If the item was indeed present and it could be retrieved.
            response.raise_for_status()

            if response.status_code == 204:
                raise VirusTotalManagerError("Error: you exceed the API request rate limit")

            if NO_DATA_FOUND_MESSAGE in response.content or response.json()['response_code'] == 0:
                return

            if RESOURCE_COULD_NOT_BE_FOUND_MESSAGE in response.content:
                return

            if response.json()['response_code'] == -1 and INVALID_MESSAGE in response.content:
                return

        except requests.HTTPError as e:
            raise VirusTotalManagerError("Error: {0}. {1}".format(e, response.text))

        return True

    def get_scan_flat_information(self, report):
        """
        returns scan report flat data - ignore report data that is lists/dicts
        :param report: {dict} full scan report information
        :return: {dict} scan report flat data.
        """
        return {key: value for key, value in report.items() if
                not isinstance(value, list) or not isinstance(value, dict)}

    def extract_detections_information(self, report):
        """
        extract_detections_information for ip and domain
        :param report: {dict} full scan report information
        :return: {dict} detections scores and related information after calculation.
        """
        max_positives = 0
        total = 0
        related = None

        for key in report.keys():
            if key.startswith('detected'):
                for detection in report[key]:
                    if detection.get('positives', 0) > max_positives:
                        max_positives = detection['positives']
                        total = detection['total']
                        related = detection.get('url') or detection.get('sha256')

        search_data = {'VT_risk_score': max_positives, 'VT_total_score': total, 'VT_related_suspicious_entity': related}
        return search_data

    @staticmethod
    def build_detection_csv(search_data):
        """
        Summarize csv for ip and domain that contain scan calculated score.
        :param search_data: {dict} scan calculated scores
        :return: {list} scan calculated score.
        """
        detection_csv = ['Risk Score, Total Score, Risk Related Object']
        detection_csv.append("{0}, {1}, {2}".format(search_data['VT_risk_score'], search_data['VT_total_score'],
                                                    search_data['VT_related_suspicious_entity']))
        return detection_csv

    @staticmethod
    def build_engine_csv(scans_report):
        """
        The csv contain all engines which scanned url/file and their detection status.
        :param scans_report: {dict} report scans data
        :return: {list} all engines which scanned the entity and their detection status.
        """
        engine_csv = ['Engine, Is Malicious, Result, Last Analysis']
        for key, value in scans_report.items():
            engine_csv.append("{0}, {1}, {2}".format(key, value.get('detected'),
                                                     value.get('result'), value.get('update')))
        return engine_csv

    @staticmethod
    def build_hash_enrichment(report):
        """
        Build file hash enrichment object from report.
        :param report: {dict} report received from Virus Total.
        :return: {dict} enrichment object.
        """
        enrichment_dict = copy.deepcopy(FILE_ENRICHMENT_PATTERN)
        enrichment_dict['MD5'] = unicode(report.get('md5'))
        enrichment_dict['SHA1'] = unicode(report.get('sha1'))
        enrichment_dict['Scan ID'] = unicode(report.get('scan_id'))
        enrichment_dict['Last Scan Date'] = unicode(report.get('scan_date'))
        enrichment_dict['Online Report Link'] = unicode(report.get('permalink'))
        enrichment_dict['Risk Score'] = "{0}/{1}".format(report.get('positives'), report.get('total'))
        if report.get('scans'):
            enrichment_dict['Detected Engines List'] = ", ".join([engine for engine in report.get('scans') if
                                                                  report.get('scans').get(engine).get('detected')])

        return enrichment_dict

    @staticmethod
    def build_url_enrichment(report):
        """
        Build URL enrichment object.
        :param report: {dict} report received from Virus Total.
        :return: {dict} enrichment object.
        """
        enrichment_dict = copy.deepcopy(URL_ENRICHMENT_PATTERN)
        enrichment_dict["Scanned URL"] = unicode(report.get('url'))
        enrichment_dict["Scan ID"] = unicode(report.get('scan_id'))
        enrichment_dict["Last Scan Date"] = unicode(report.get('scan_date'))
        enrichment_dict["Online Report Link"] = unicode(report.get('permalink'))
        enrichment_dict["Risk Score"] = "{0}/{1}".format(report.get('positives'), report.get('total'))
        if report.get('scans'):
            enrichment_dict["Detected Engines List"] = ", ".join([engine for engine in report.get('scans') if
                                                                  report.get('scans').get(engine).get('detected')])

        return enrichment_dict

    @staticmethod
    def build_domain_enrichment(report):
        """
        Build URL enrichment object.
        :param report: {dict} report received from Virus Total.
        :return: {dict} enrichment object.
        """
        enrichment_dict = copy.deepcopy(DOMAIN_ENRICHMENT_PATTERN)
        enrichment_dict['Categories'] = ', '.join(report.get('categories')) if isinstance(report.get('categories'),
                                                                                          list) else unicode(
            report.get('categories'))
        enrichment_dict['Bit Defender Category'] = unicode(report.get('BitDefender category'))
        enrichment_dict['Bit Defender Domain Info'] = unicode(report.get('BitDefender domain info'))
        enrichment_dict['Alexa Category'] = unicode(report.get('Alexa category'))
        enrichment_dict['Alexa Domain Info'] = unicode(report.get('Alexa domain info'))
        enrichment_dict['Forcepoint ThreatSeeker Category'] = unicode(report.get('Forcepoint ThreatSeeker category'))
        # last scan date is the current time
        enrichment_dict["Latest_scan_date"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return enrichment_dict

    @staticmethod
    def build_address_enrichment(report):
        """
        Build address enrichment object.
        :param report: {dict} report received from Virus Total.
        :return: {dict} enrichment object.
        """
        enrichment_dict = copy.deepcopy(ADDRESS_ENRICHMENT_PATTERN)
        enrichment_dict['Country'] = report.get('country')
        enrichment_dict['Related Domains'] = ", ".join([resolution['hostname'] for resolution in report.get('resolutions', [])])
        # last scan date is the current time
        enrichment_dict["Latest_scan_date"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return enrichment_dict

    def define_resource_status(self, resource, resource_type, rescan_after_days=None):
        """
        Check if entity need to be rescanned, if entity is missing in VT or if fetch an existing report
        :param resource: {string} entity identifier - resource to search in VT
        :param resource_type: {string} hash/url
        :param rescan_after_days: {int} parameter to determine how many days after to rescan
        :return: {dict} entity details
        """
        resource_handle = {resource: {ENTITY_REPORT_KEY: {}, ENTITY_TASK_ID_KEY: None, ENTITY_STATUS_KEY: None}}
        rescan_resources = []

        is_rescan = False
        current_time = datetime.now()

        # Get report
        report = self.get_url_or_file_report(resource, resource_type)
        if report:
            report_scan_date = datetime.strptime(report.get("scan_date"), "%Y-%m-%d %H:%M:%S")
            if rescan_after_days:
                is_rescan = (current_time - report_scan_date).days >= rescan_after_days

            if is_rescan:
                rescan_resources.append(resource)
            else:
                resource_handle[resource][ENTITY_REPORT_KEY] = report
                resource_handle[resource][ENTITY_STATUS_KEY] = ScanStatus.DONE
        else:
            # this resource is missing - not exist in Virus Total
            resource_handle[resource][ENTITY_STATUS_KEY] = ScanStatus.MISSING

        if rescan_resources:
            scan_id = None

            if resource_type == FILEHASH_TYPE:
                # Rescan file.
                scan_id = self.rescan_file(resource)
            if resource_type == URL_TYPE:
                # rescan url
                scan_id = self.scan_url(resource.lower())
            if scan_id:
                resource_handle[resource][ENTITY_TASK_ID_KEY] = scan_id
                resource_handle[resource][ENTITY_STATUS_KEY] = ScanStatus.QUEUED
            else:
                # this resource is missing - not exist in Virus Total
                resource_handle[resource][ENTITY_STATUS_KEY] = ScanStatus.MISSING

        return resource_handle

    def is_scan_report_ready(self, task_id, resource_type):
        """
        check if scan report is still queued or ready
        :param task_id: {string} scan id
        :param resource_type: {string} hash/url
        :return: {dict} resource report of none
        """
        report = self.get_url_or_file_report(task_id, resource_type)
        status = report.get('response_code')
        if status != QUEUED_FOR_ANALYSIS:
            return report


