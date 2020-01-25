# ==============================================================================
# title           :AlienVaultTIManager.py
# description     :This Module contain all AlienVault TI cloud operations functionality
# author          :zdemoniac@gmail.com
# date            :1-18-18
# python_version  :2.7
# libraries       : json, requests, urllib2
# requirements    :
# product_version :
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================
import json
import requests
import urllib2

# =====================================
#             CONSTANTS               #
# =====================================
API_URL = "https://otx.alienvault.com:443/api/v1/"
API_KEY = "23596d8dc6758090299cfe2638630d23f8636cc60247df38aab4cc43a10555ec"

SKIP_FIELDS = ['general']
IP_IS_PRIVATE_ERROR_MSG = 'IP is private'


# =====================================
#              CLASSES                #
# =====================================
class AlienVaultTIManagerError(Exception):
    """
    General Exception for DShield manager
    """
    pass


class AlienVaultTIManager(object):
    """
    Responsible for all AlienVault TI system operations functionality
    API docs: https://otx.alienvault.com/api
	Supports only general section
    """
    def __init__(self, api_key):
        self._api_url = API_URL
        self._headers = {"X-OTX-API-KEY": api_key, "Content-Type": "application/json"}

    def test_connectivity(self):
        """
        Validates connectivity
        :return: {boolean} True/False
        """
        try:
            # Dummy requests
            self._get("indicators/hostname/localhost")
            return True
        except AlienVaultTIManagerError:
            return False

    def enrich_host(self, host):
        """
        Get host info from AlienVault
        :param host: {string} a valid host
        :return: {dict}
        """
        results = {}
        host_lower = host.lower()
        sections_results = self._get("indicators/hostname/" + host_lower)
        if sections_results:
            for section in sections_results['sections']:
                results[section] = self._get("indicators/hostname/{0}/{1}".format(host_lower, section))
            return results

    def enrich_ip(self, ip):
        """
        Get ip info from AlienVault
        :param ip: {string} a valid IP address
        :return: {dict}
        """
        results = {}
        sections_results = self._get("indicators/IPv4/" + ip)
        if sections_results:
            for section in sections_results['sections']:
                results[section] = self._get("indicators/IPv4/{0}/{1}".format(ip, section))
            return results

    def enrich_url(self, url):
        """
        Get ip info from AlienVault
        :param url: {string}
        :return: {dict}
        """
        results = {}
        url_lower = url.lower()
        sections_results = self._get("indicators/url/{}/general".format(urllib2.quote(url_lower)))
        if sections_results:
            for section in sections_results['sections']:
                results[section] = self._get("indicators/url/{0}/{1}".format(urllib2.quote(url_lower), section))
            return results

    def enrich_hash(self, file_hash):
        """
        Get ip info from AlienVault
        :param file_hash: {string} file hash
        :return: {dict}
        """
        results = {}
        sections_results = self._get("indicators/file/" + file_hash)
        if sections_results:
            for section in sections_results['sections']:
                results[section] = self._get("indicators/file/{0}/{1}".format(file_hash, section))
            return results

    def _get(self, func):
        """
        Get and return data from the API.
        :return: {dict}
        """
        r = requests.get(''.join([self._api_url, func]), headers=self._headers)
        # Return none if no results where found
        if r.status_code == 404:
            return None
        # This situation is equivalent to 404 no results where found
        if r.status_code == 400 and IP_IS_PRIVATE_ERROR_MSG in r.content:
            return None
        try:
            r.raise_for_status()
        except Exception as error:
            raise AlienVaultTIManagerError("Error: in {}  {} {}".format(func, error, r.text))
        return r.json()


if __name__ == "__main__":
    av = AlienVaultTIManager(API_KEY)

    r = av.test_connectivity()

    r = av.enrich_host("WWW.IRCNET.ORG")

    r = av.enrich_ip("10.128.2.13")

    r = av.enrich_url("https://www.facebook.com")

    r = av.enrich_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")