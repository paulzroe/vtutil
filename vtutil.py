#!/usr/bin/env python
from __future__ import print_function

__description__ = "Python Utility for Virustotal"
__author__ = 'PaulK'
__version__ = '0.0.1'
__date__ = '2020/07/30'

"""
History:
    2020/07/30: start

"""

import requests
import os
import re
import hashlib
import argparse
import json
import pefile
import logging
import vtutilconstants as vtc
from pprint import pprint


def save_downloaded_file(filename, save_file_at, file_stream):
    """ Save Downloaded File to Disk Helper Function
    :param save_file_at: Path of where to save the file.
    :param file_stream: File stream
    :param filename: Name to save the file.
    :returns True if success else False
    """
    filename = os.path.join(save_file_at, filename)
    with open(filename, 'wb') as f:
        f.write(file_stream)
        f.flush()
    if os.path.isfile(filename):
        return True
    else:
        return False


def hash_for_file(filepath):
    """ Get hashes of file
    :param filepath: Path of the file
    :returns json result of hashes
    """
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), ''):
                sha256.update(chunk)
                sha1.update(chunk)
                md5.update(chunk)
        f.close()
        return {'response_code': 1,
                'md5': md5.hexdigest(),
                'sha1': sha1.hexdigest(),
                'sha256': sha256.hexdigest()}

    except Exception as e:
        return {'response_code': -1,
                'error': repr(e)}


def getRawScans(jsonData):
    """
    Gets scans from all AV
    :param jsonData: from getFileReport
    :return: dict {"av": "detection"}
    """

    scans = {}
    if 'scans' in jsonData:
        for engine, signature in jsonData.get("scans").items():
            if signature['detected']:
                avEngine_ = engine.lower()
                avEngine = re.sub(r'[\+-]', "_", avEngine_)
                scans[avEngine] = signature['result']

    return scans


def get_combined_cat_family(self, category, family, ms_category, ms_family):
    combined_category, combined_family = None, None

    if ms_category is None and ms_family is None:
        return category, family

    else:
        normalized_ms_family = re.split(r'\/|!', ms_family)[1]
        if ms_family in vtc.MS_FAMILY_BLACKLIST:
            return category, family

        elif normalized_ms_family.lower() in vtc.MS_FAMILY_GENERIC:
            return category, family
        else:
            return ms_category, normalized_ms_family.lower()


def isfamilyreadable(family):
    VOWELS = "aeiou"
    PHONES = ['sh', 'ch', 'ph', 'sz', 'cz', 'sch', 'rz', 'dz']
    if family:
        consecutiveVowels = 0
        consecutiveConsonents = 0
        for idx, letter in enumerate(family.lower()):
            vowel = True if letter in VOWELS else False

            if idx:
                prev = family[idx - 1]
                prevVowel = True if prev in VOWELS else False
                if not vowel and letter == 'y' and not prevVowel:
                    vowel = True

                if prevVowel != vowel:
                    consecutiveVowels = 0
                    consecutiveConsonents = 0

            if vowel:
                consecutiveVowels += 1
            else:
                consecutiveConsonents += 1

            if consecutiveVowels >= 3 or consecutiveConsonents > 3:
                return False

            if consecutiveConsonents == 3:
                subStr = family[idx - 2:idx + 1]
                if any(phone in subStr for phone in PHONES):
                    consecutiveConsonents -= 1
                    continue
                return False

    return True


def normalize_malware_names_step1(malwarenames):
    # malwarenames-list to string

    names = " ".join(malwarenames)
    for trn in vtc.TRENNER:
        names = names.replace(trn, " ").lower()

    for key in sorted(vtc.MAPPING, key=len, reverse=True):
        names = names.replace(key, vtc.MAPPING[key])

    return names


def normalize_malware_names_step2(names):
    # sort Replace Map
    vtc.REPLACE.sort(key=lambda item: (-len(item), item))
    # delete not usable words
    for r in vtc.REPLACE:
        names = names.replace(r, " ")

    # delete special characters
    names = "".join(re.findall("[a-z\s]*", names))
    # delete multiple whitespaces
    names = re.sub('\s{2,}', ' ', names)
    # delete small words
    tmpNames = []
    for name in names.strip().split(' '):
        if len(name.strip()) > 3:
            tmpNames.append(name.strip())

    # print tmpNames
    return tmpNames


def simpleWordFrequency(tmpNames):
    # find the most frequently occuring words
    wordCount = {}
    for wort in tmpNames:
        w = wort.strip()
        if len(w) > 0:
            wordCount[w] = wordCount.get(w, 0) + 1

    return wordCount


"""
def getClassification(self, jsonData):
    malwarenames = []
    family = None
    category = None
    microsoft = None
    ms_family = None
    ms_category = None
    combined_category = None
    combined_family = None

    scans = self.getRawScans(jsonData)
    for engine, detection in scans.items():
        if engine in vtc.TRUSTEDAV:
            if engine == 'microsoft':
                microsoft = detection
            if 'Artemis' in detection:
                continue
            malwarenames.append(detection)

    if microsoft is not None:
        # print microsoft
        if ":" in microsoft:
            ms_category, malware_name = microsoft.split(":")
            ms_family = malware_name.split('.')[0]
        # return malware_category, malware_name_no_variant

    if len(malwarenames) == 0:
        return category, family, ms_category, ms_family, combined_category, combined_family
    names = self.normalize_malware_names_step1(malwarenames)
    # print names
    categoryDict = vtc.CATEGORY
    for key in categoryDict:
        categoryDict[key] = names.count(key.lower())
    for key in sorted(categoryDict, key=categoryDict.get, reverse=True):
        category = key
        break

    # category
    names = self.normalize_malware_names_step2(names)
    wordCountMap = self.simpleWordFrequency(names)
    foundAgent = False
    # This is just to avoid agent family
    # print wordCountMap

        for key in sorted(wordCountMap, key=wordCountMap.get, reverse=True):
            count = wordCountMap[key]

            if count > 2:
                family = key
                break
            if len(key) > 7:
                family = key
                break
            if self.isfamilyreadable(key) == True:
                family = key
                break

        # if category == 'Trojan' or category == 'Riskware' or category == 'PUA' or category == 'Ransomware':
        if family in vtc.KNOWN_ADWARE_LIST:
            category = 'Adware'

        # Try fix invalid family names
        if family is not None:
            if len(family) < 5:
                if self.isfamilyreadable(family) == False:
                    family = 'unknown'

        if category is not None and family is None:
            family = "generic"

        combined_category, combined_family = self.get_combined_cat_family(category, family, ms_category, ms_family)

        return category, family, ms_category, ms_family, combined_category, combined_family
"""


def getClassificationFromScans(scans):
    """
    Returns a family and category by using malwarebytes, microsoft and by occurence of words in that order

    :param scans: a dict of av and their detections
    :return: dict which contains family, category and the following detections (malwarebytes, microsoft, kaspersky, sophos)
    """
    malwarenames = []
    family = None
    category = None
    microsoft = None
    malwarebytes = None
    ms_family = None
    ms_category = None
    combined_category = None
    combined_family = None

    classification = {"family": family,
                      "category": category,
                      "av": {"kaspersky": scans.get("kaspersky"),
                             "malwarebytes": scans.get("malwarebytes"),
                             "microsoft": scans.get("microsoft"),
                             "sophos": scans.get("sophos")}
                      }

    for engine, detection in scans.items():
        if engine in vtc.TRUSTEDAV:
            if 'Artemis' in detection:
                continue
            malwarenames.append(detection)

    if len(malwarenames) == 0:
        return classification

    malwarebytes = scans.get('malwarebytes')
    microsoft = scans.get('microsoft')

    # Use malwarebytes family as priority
    if malwarebytes:
        malwarebytes_split = malwarebytes.split(".")
        ms_category = malwarebytes_split[0]
        ms_family = "_".join(malwarebytes_split[1:]).lower()

        for mbgeneric in vtc.MALWAREBYTES_GENERIC:
            if mbgeneric in ms_family:
                malwarebytes = None

    # microsft
    if malwarebytes is None and microsoft is not None:
        if ":" in microsoft:
            ms_category, malware_name = microsoft.split(":")
            ms_family = malware_name.split('.')[0]
            normalized_ms_family = re.split(r'\/|!', ms_family)[1]
            ms_family = normalized_ms_family.lower()
            if ms_family in vtc.MS_FAMILY_GENERIC:
                microsoft = None

    if malwarebytes is not None or microsoft is not None:
        classification["family"] = ms_family
        classification["category"] = ms_category
        return classification

    else:
        names = normalize_malware_names_step1(malwarenames)

        categoryDict = vtc.CATEGORY
        for key in categoryDict:
            categoryDict[key] = names.count(key.lower())
        for key in sorted(categoryDict, key=categoryDict.get, reverse=True):
            category = key
            break

        # category
        names = normalize_malware_names_step2(names)
        wordCountMap = simpleWordFrequency(names)

        for key in sorted(wordCountMap, key=wordCountMap.get, reverse=True):
            count = wordCountMap[key]

            # first priority, if this family occured more than 2 times
            if count > 2:
                family = key
                break

            # if occured 2 times or less, choose the one that has length greater than 7
            if len(key) > 7:
                family = key
                break

            # if occured 2 times or less, check if the family is readable
            if isfamilyreadable(key) == True:
                family = key
                break

        # if category == 'Trojan' or category == 'Riskware' or category == 'PUA' or category == 'Ransomware':
        if family in vtc.KNOWN_ADWARE_LIST:
            category = 'Adware'

        # Try fix invalid family names
        if family is not None:
            if len(family) < 5:
                if isfamilyreadable(family) == False:
                    family = 'unknown'

        if category is not None and family is None:
            family = "generic"

        classification["family"] = family
        classification["category"] = category

        return classification


class VTUtilsV3:
    PCAP_URL = vtc.BASE_URL + 'api/v3/file_behaviours/'
    FILE_URL = vtc.BASE_URL + 'api/v3/files/'
    IP_URL = vtc.BASE_URL + 'api/v3/ip_addresses/'
    DOMAIN_URL = vtc.BASE_URL + 'api/v3/domains/'
    SEARCH_URL = vtc.BASE_URL + 'api/v3/intelligence/search'
    RETROHUNT_URL = vtc.BASE_URL + 'api/v3/intelligence/retrohunt_jobs'
    LIVE_HUNT_NOTIFICATION = vtc.BASE_URL + 'api/v3/intelligence/hunting_notifications'
    LIVE_HUNT_NOTIFICATION_FILES = vtc.BASE_URL + 'api/v3/intelligence/hunting_notification_files'
    LIVE_HUNT_RULESETS = vtc.BASE_URL + 'api/v3/intelligence/hunting_rulesets'


    def __init__(self, api_key=None, debug=False):
        if api_key == None:
            raise Exception('Please supply an API KEY')
        else:
            self.APIKEY = api_key
            self.debug = debug
            requests.packages.urllib3.disable_warnings()

    def get_file(self, file_hash, save_file_at):
        """

        :param file_hash: sha256, sha1, or md5
        :param save_file_at: directory on where to save the file
        :return:
        """

        headers = {'x-apikey': self.APIKEY}

        download_uri = self.FILE_URL + file_hash + '/download'
        for i in range(1, 3):
            try:
                response = requests.get(download_uri, headers=headers)
            except:
                continue

        if response.status_code == requests.codes.ok:
            try:
                save_downloaded_file(file_hash, save_file_at, response.content)
                return True
            except:
                return False


    def getfileReportv3(self, hash):
        # gets behavior for files
        headers = {'x-apikey': self.APIKEY}
        file_uri = self.FILE_URL + hash
        for i in range(1, 3):
            try:
                response = requests.get(file_uri, headers=headers)
                return response.json()
            except:
                continue

        return None

    def getfileBehaviorv3(self, hash):
        # gets behavior for files
        headers = {'x-apikey': self.APIKEY}
        file_uri = self.FILE_URL + hash + '/behaviours'
        for i in range(1, 3):
            try:
                response = requests.get(file_uri, headers=headers)
                return response.json()
            except:
                continue

        return None

    def getfileRelationshipv3(self, hash, relationships):
        # relationship is comma separated
        # contacted_domains
        # contacted_ips
        # contacted_urls
        # execution_parents
        # itw_urls
        # pcap_parents
        # email_parents
        # embedded_urls
        # embedded_ips
        # embedded_domains
        # sigma_analysis - gives you only links
        # similar_files
        # comments - gives you only links
        # analyses  - contains links only
        # behaviours  - contains links only

        params = {'relationships': relationships}
        headers = {'x-apikey': self.APIKEY}
        file_uri = self.FILE_URL + hash
        for i in range(1, 3):
            try:
                response = requests.get(file_uri, params=params, headers=headers)
                return response.json()
            except:
                continue

        return None

    def getIPReportv3(self, ipv4):
        headers = {'x-apikey': self.APIKEY}
        file_uri = self.IP_URL + ipv4
        for i in range(1, 3):
            try:
                response = requests.get(file_uri, headers=headers)
                return response.json()
            except:
                continue

        return None

    def getIPRelationshipv3(self, ipv4, relationship, limit=10):
        # relationship variable could include the following:
        # communicating_files
        # downloaded_files
        # graphs
        # historical_whois
        # referrer_files
        # resolutions
        # urls

        params = {'limit': limit}
        headers = {'x-apikey': self.APIKEY}
        file_uri = self.IP_URL + ipv4 + '/' + relationship
        for i in range(1, 3):
            try:
                response = requests.get(file_uri, params=params, headers=headers)
                if response.status_code == 404:
                    return {"error": "Not Found",
                            "return code": response.status_code,
                            "response_code": -1}
                return response.json()
            except:
                continue

        return {"error": "Exception",
                "response_code": -1}

    def getDomainReportv3(self, domain):
        headers = {'x-apikey': self.APIKEY}
        file_uri = self.DOMAIN_URL + domain
        for i in range(1, 3):
            try:
                response = requests.get(file_uri, headers=headers)
                return response.json()
            except:
                continue

        return None

    def getDomainRelationshipv3(self, domain, relationship, limit=10):
        # relationship variable could include the following:
        # communicating_files
        # downloaded_files
        # graphs
        # historical_whois
        # referrer_files
        # resolutions
        # siblings
        # subdomains
        # urls
        params = {'limit': limit}
        headers = {'x-apikey': self.APIKEY}
        file_uri = self.DOMAIN_URL + domain + '/' + relationship
        for i in range(1, 3):
            try:
                response = requests.get(file_uri, params=params, headers=headers)
                if response.status_code == 404:
                    return {"error": "Not Found",
                            "return code": response.status_code}
                return response.json()
            except:
                continue

        return {"error": "Exception"}

    def searchv3(self, search_string=None, limit=10):
        params = {'limit': limit,
                  'query': search_string}
        headers = {'x-apikey': self.APIKEY}

        file_uri = self.SEARCH_URL
        for i in range(1, 3):
            try:
                response = requests.get(file_uri, params=params, headers=headers)
                if response.status_code == 404:
                    return {"error": "Not Found",
                            "return code": response.status_code,
                            "response_code": -1}
                return response.json()
            except:
                continue

        return {"error": "Exception",
                "response_code": -1}

    def getfileSubmissionsv3(self, hash):
        headers = {'x-apikey': self.APIKEY}
        file_uri = self.FILE_URL + hash + '/submissions'
        for i in range(1, 3):
            try:
                response = requests.get(file_uri, headers=headers)
                return response.json()
            except:
                continue

        return None

    def getPcapv3(self, hash, sandbox_id, save_file_at):
        headers = {'x-apikey': self.APIKEY}
        pcap_uri = self.PCAP_URL + hash + sandbox_id + '/pcap'
        # print pcap_uri
        response = requests.get(pcap_uri, headers=headers)
        # print response.url
        print(response.status_code)
        if response.status_code == requests.codes.ok:
            try:
                save_downloaded_file(hash + '.pcap', save_file_at, response.content)
            except:
                raise
        return response.status_code

    def get_hunting_rulesets(self, filter=None, limit=10):
        """
        returns the list of hunting rulesets you created. It includes disabled rules.
        :reference https://developers.virustotal.com/v3.0/reference#list-hunting-rulesets
        :param limit:
        :param filter: e.g enable:true, name:foo. You can also have multiple filters e.g. filter=enabled:true name:foo
        :return:
        """
        headers = {'x-apikey': self.APIKEY}

        params = {'limit': limit,
                  'filter': filter}
        response = requests.get(self.LIVE_HUNT_RULESETS, params=params, headers=headers)
        return response.json()

    def post_hunting_rulesets(self, rule_string, name, enabled=False, limit=100):
        """
        :param body: json format containing like below. name and rules are required. Others are optional
            {
              "data": {
                "type": "hunting_ruleset",
                "attributes": {
                  "name": "foobar",
                  "enabled": true,
                  "limit": 100,
                  "rules": "rule foobar { strings: $ = \"foobar\" condition: all of them }",
                  "notification_emails": ["wcoyte@acme.com", "rrunner@acme.com"]
                }
              }
            }
        :return:
        :reference https://developers.virustotal.com/v3.0/reference#create-hunting-ruleset
        """

        headers = {'x-apikey': self.APIKEY}
        rule_type = "hunting_ruleset"
        data = {
            "data": {
                "type": rule_type,
                "attributes": {
                    "name": name,
                    "enabled": enabled,
                    "limit": limit,
                    "rules": rule_string
                }
            }
        }
        response = requests.post(self.LIVE_HUNT_RULESETS, data=json.dumps(data), headers=headers)
        return response.json()


    def get_hunting_notifications(self, filter=None, limit=10, cursor=None):
        """
        This is not much useful as it does not return you the file. Look for get_hunting_notification_files
        :param filter: Rule Name or String
        :param limit: By default is 10. Max is 40
        :return: a list of notifications
        :reference: https://developers.virustotal.com/v3.0/reference#list-hunting-notifications
        """

        max_limit = 40 # We always set the limit at 40 as we probably want to look for more than that anyway

        headers = {'x-apikey': self.APIKEY}
        params = {'filter': filter,
                  'limit': max_limit,
                  'cursor': cursor}

        hunt_notifications = []

        while len(hunt_notifications) < limit:
            response = requests.get(self.LIVE_HUNT_NOTIFICATION, params=params, headers=headers)
            hunt_notifications.extend(response.json().get("data"))

            params["cursor"] = response.json().get("meta", {}).get("cursor")

        if len(hunt_notifications) > limit:

            return hunt_notifications[:limit]

    def get_hunting_notification_files(self, filter=None, limit=10, cursor=None):
        """
        :param filter: Rule Name or String
        :param limit: By default is 10. Max is 40
        :return: a list of notifications
        :reference: https://developers.virustotal.com/v3.0/reference#list-hunting-notifications
        """

        max_limit = 40  # We always set the limit at 40 as we probably want to look for more than that anyway

        headers = {'x-apikey': self.APIKEY}
        params = {'filter': filter,
                  'limit': max_limit,
                  'cursor': cursor}

        hunt_notifications = []

        while len(hunt_notifications) < limit:
            response = requests.get(self.LIVE_HUNT_NOTIFICATION_FILES, params=params, headers=headers)
            hunt_notifications.extend(response.json().get("data"))
            logging.debug("Getting cursor: {}".format(response.json().get("meta", {}).get("cursor")))
            params["cursor"] = response.json().get("meta", {}).get("cursor")

        if len(hunt_notifications) > limit:
            return hunt_notifications[:limit]
        return hunt_notifications

    def getRetrohuntMatchingFiles(self, retrohunt_id, cursor=None, limit=10):
        headers = {'x-apikey': self.APIKEY}

        params = {'cursor': cursor, 'limit': limit}

        matching_files_uri = self.RETROHUNT_URL + retrohunt_id + '/matching_files'
        # print pcap_uri
        for i in range(1, 3):
            try:
                response = requests.get(matching_files_uri, params=params, headers=headers)
                if response.status_code == 404:
                    return {"error": "Not Found",
                            "return code": response.status_code,
                            "response_code": -1}
                return response.json()
            except:
                continue

        return {"error": "Exception",
                "response_code": -1}

    def getRetrohuntJobs(self, cursor=None):

        headers = {'x-apikey': self.APIKEY}

        params = {'cursor': cursor}

        retrohunt_jobs = self.RETROHUNT_URL
        # print pcap_uri
        for i in range(1, 3):
            try:
                response = requests.get(retrohunt_jobs, params=params, headers=headers)
                if response.status_code == 404:
                    return {"error": "Not Found",
                            "return code": response.status_code}
                return response.json()
            except:
                raise

        return {"error": "Exception"}

    def submitRetrohuntJob(self, rule_string, corpus='main'):

        headers = {'x-apikey': self.APIKEY}

        data = {"data": {"type": "retrohunt_job", "attributes": {"rules": rule_string, "corpus": corpus}}}
        pprint(data)
        retrohunt_jobs = self.RETROHUNT_URL
        # print pcap_uri

        for i in range(1, 3):
            try:
                response = requests.post(retrohunt_jobs, headers=headers, data=json.dumps(data))
                if response.status_code == 404:
                    return {"error": "Not Found",
                            "return code": response.status_code}
                return response.json()
            except:
                raise

        return {"error": "Exception"}

    def vtQuery(self, query, cursor=None):
        if cursor is None:
            params = {'query': query, 'limit': 300, 'descriptors_only': True}

        else:
            params = {'query': query, 'limit': 300, 'cursor': cursor, 'descriptors_only': True}

        headers = {'x-apikey': self.APIKEY}
        response = requests.get(self.SEARCH_URL, headers=headers, params=params)

        try:
            response_json = response.json()
            return response_json
        except:
            return None

    def getHashesv3(self, query, count=300):
        hashes = []
        response_json = self.vtQuery(query)
        proceed = True
        # print json.dumps(response_json)
        try:
            for data in response_json.get("data"):
                hashes.append(data.get('id'))
            hashcount = len(hashes)
            while hashcount < count:
                if response_json.get('meta').get('cursor') is not None:
                    response_json = self.vtQuery(query, cursor=response_json.get('meta').get('cursor'))
                    for data in response_json.get("data"):
                        hashes.append(data.get('id'))
                    hashcount = len(hashes)
                else:
                    return hashes

            return hashes
        except:
            return hashes

        # return hashes

    def getRawscansv3(self, jsonData):
        scans = {}

        if jsonData.get("data", {}).get("attributes", {}).get("last_analysis_results") is not None:
            for engine, signature in jsonData.get("data", {}).get("attributes", {}).get(
                    "last_analysis_results").items():
                if signature['result'] is not None:
                    avEngine_ = engine.lower()
                    avEngine = re.sub(r'[\+-]', "_", avEngine_)
                    scans[avEngine] = signature['result']

        return scans

    def getClassification(self, jsonData):
        scans = self.getRawscansv3(jsonData)
        return getClassificationFromScans(scans)

    def getsignerhashes(self, signer, search_string=None):
        """

        :param signer:
        :param search_string:
        :return:
        """

        hashes = None
        # search 30 samples in VT with same signer
        query = 'sigcheck:"%s" and tag:signed' % signer
        if search_string:
            query += ' and %s' % search_string

        if self.debug:
            print("Query: ", query)

        vtResponse = VTUtilsV3.vtQuery(query)

        # ##REDO THE QUERY FOR OPTIMIZATION
        foundSignerRaw = False
        signer_raw = signer
        if vtResponse is not None:
            if vtResponse.get('response_code') == 1:
                hashes = vtResponse.get('hashes')

                for sha256 in hashes:
                    vtFileReport = VTUtilsV3.getfileReportv3(sha256)
                    try:
                        signer_raw = vtFileReport.get('additional_info').get('sigcheck').get('signers')
                        if signer_raw is None:
                            continue
                        if signer == signer_raw.split(';')[0]:
                            foundSignerRaw = True
                            break
                    except:
                        continue
        # we need to requery twice to have a more specific query, e.g., including the secondary signers
        if foundSignerRaw == True:
            vtResponse = VTUtilsV3.vtQuery('sigcheck:"%s" and tag:signed and (tag:peexe or tag:pedll)' % signer_raw)

            if vtResponse != None:
                if vtResponse.get('response_code') == 1:
                    return vtResponse.get('hashes')

        else:
            return hashes


class VTUtilsV2:
    VT_SEARCH_URL = vtc.BASE_URL + 'vtapi/v2/file/search'
    VT_REPORT_URL = vtc.BASE_URL + 'vtapi/v2/file/report'
    VT_DOMAIN_REPORT_URL = vtc.BASE_URL + 'vtapi/v2/domain/report'
    VT_URL_REPORT_URL = vtc.BASE_URL + 'vtapi/v2/url/report'
    VT_IP_REPORT_URL = vtc.BASE_URL + 'vtapi/v2/ip-address/report'
    VT_COMMENTS_URL = vtc.BASE_URL + 'vtapi/v2/comments/get'
    VT_CLUSTERS_URL = vtc.BASE_URL + 'vtapi/v2/file/clusters'
    VT_DOWNLOAD_URL = vtc.BASE_URL + 'vtapi/v2/file/download'
    VT_RESCAN_URL = vtc.BASE_URL + 'vtapi/v2/file/rescan'
    TRENNER = [".", ":", "-", "~", "@", "!", "/", "_", ";", "[", "]", "(", ")"]

    def __init__(self, api_key=None, debug=False):
        if api_key == None:
            raise Exception('Please supply an API KEY')
        else:
            self.APIKEY = api_key
            self.debug = debug
            requests.packages.urllib3.disable_warnings()

    def get_VTfile(self, file_hash, save_file_at):
        """ Get the scan results for a file.
        Even if you do not have a Private Mass API key that you can use, you can still download files from the
        VirusTotal storage making use of your VirusTotal Intelligence quota, i.e. programmatic downloads will
        also deduct quota.
        :param file_hash: You may use either the md5, sha1 or sha256 hash of the file in order to download it.
        :param save_file_at: Path of where to save the file.
        """
        params = {'apikey': self.APIKEY, 'hash': file_hash}

        try:
            response = requests.get(self.VT_DOWNLOAD_URL, params=params)
        except requests.RequestException as e:
            return dict(error=e.message)

        if response.status_code == requests.codes.ok:
            try:
                save_downloaded_file(file_hash, save_file_at, response.content)
            except:
                return None
            return response.status_code

        elif response.status_code == 403:
            return dict(error='You tried to perform calls to functions for which you require a Private API key.',
                        response_code=response.status_code)
        elif response.status_code == 404:
            return dict(error='File not found.', response_code=response.status_code)
        else:
            return dict(response_code=response.status_code)

    def getFileType(self, jsonData):
        # placeholder for file type in VT
        # sometimes DMG files are classified as unknown
        if jsonData.get('type') == 'unknown':
            trid = jsonData.get('additional_info').get('trid')
            if trid is None:
                return jsonData.get('type')
            if "Disk Image (Macintosh)" in trid:
                return "Macintosh Disk Image"

        return jsonData.get('type')

    # Added May 10, 2016
    def getCyRepScore(self, jsonData):
        # get number of hits based on CY trusted list
        # returns an integer or None
        if 'scans' in jsonData:
            CyReputationScore = 0
            for engine, signature in jsonData.get("scans").items():
                if signature['detected']:
                    avEngine_ = engine.lower()
                    avEngine = re.sub(r'[\+-]', "_", avEngine_)
                    if avEngine in vtc.CY_TRUSTED_AV:
                        CyReputationScore += 1

            return CyReputationScore
        else:
            return None

    def getScans(self, jsonData):
        # get scans from known AVlist only
        scans = {}
        if 'scans' in jsonData:
            for engine, signature in jsonData.get("scans").items():
                if signature['detected']:
                    avEngine_ = engine.lower()
                    avEngine = re.sub(r'[\+-]', "_", avEngine_)
                    if avEngine in vtc.AVLIST:
                        scans[avEngine] = signature['result']

        return scans

    def process_url(self, url):
        if re.match(r'^http*\:\/\/', url):
            domain = url.split("://")[1].split("/")[0]
        else:
            domain = url.split("/")[0]

        if re.match(r'\:', domain):
            domain_wo_port = domain.split(":")[0]
            return domain_wo_port
        else:
            return domain

    def vtQuery(self, query, offset=None):
        if offset == None:
            params = {'apikey': self.APIKEY, 'query': query}

        else:
            params = {'apikey': self.APIKEY, 'query': query, 'offset': offset}
        response = requests.get(self.VT_SEARCH_URL, params=params)

        try:
            response_json = response.json()
            return response_json
        except:
            return None

    def vtClusters(self, query, offset=None):
        if offset == None:
            params = {'apikey': self.APIKEY, 'query': query}
        else:
            params = {'apikey': self.APIKEY, 'query': query, 'offset': offset}
        response = requests.get(self.VT_SEARCH_URL, params=params)
        try:
            response_json = response.json()
            return response_json
        except:
            return None

    def getHashes(self, query, count=300):
        hashes = []
        response_json = self.vtQuery(query)
        proceed = True
        # print json.dumps(response_json)
        try:
            hashes = response_json["hashes"]
            hashcount = len(hashes)
            while hashcount < count:
                if response_json.get('offset') != None:
                    response_json = self.vtQuery(query, offset=response_json.get('offset'))
                    hashes.extend(response_json.get('hashes'))
                    hashcount = len(hashes)
                else:
                    return hashes[:count]

            return hashes[:count]
        except:
            return hashes

    # return hashes

    def rescan(self, hash):
        params = {'apikey': self.APIKEY, 'resource': hash}
        for i in range(1, 3):
            try:
                response = requests.post(self.VT_RESCAN_URL, params=params)
                return response.json()
            except:
                continue

        return None

    def getfileReport(self, hash):
        params = {'apikey': self.APIKEY, 'resource': hash, 'allinfo': 1}
        for i in range(1, 3):
            try:
                response = requests.get(self.VT_REPORT_URL, params=params)
                return response.json()
            except:
                continue

        return None

    def getDomainReport(self, domain):
        params = {'domain': domain, 'apikey': self.APIKEY, 'allinfo': 1}
        response = requests.get(self.VT_DOMAIN_REPORT_URL, params=params)
        response_json = response.json()
        return response_json

    def getUrlReport(self, url):
        params = {'resource': url, 'apikey': self.APIKEY, 'allinfo': 1}
        response = requests.get(self.VT_URL_REPORT_URL, params=params)
        try:
            response_json = response.json()
        except:
            response_json = None
        return response_json

    def getIpReport(self, url):
        params = {'ip': url, 'apikey': self.APIKEY}
        response = requests.get(self.VT_IP_REPORT_URL, params=params)
        response_json = response.json()
        return response_json

    def getClassification(self, jsonData):
        scans = getRawScans(jsonData)
        return getClassificationFromScans(scans)

    def getComments(self, hash):
        params = {'apikey': self.APIKEY, 'resource': hash, 'allinfo': 1}
        response = requests.get(self.VT_COMMENTS_URL, params=params)
        response_json = response.json()
        return response_json

    def getVTDetails(self, hash):
        report = self.getfileReport(hash)

        if report.get('response_code') == 0:
            return None
        submissionNames = report.get('submission_names')

        magicFileType = report.get('additional_info').get('magic')
        try:
            publisher = report.get('additional_info').get('sigcheck').get('publisher')
        except:
            publisher = None

        try:
            signers = report.get('additional_info').get('sigcheck').get('signers')
            signers = signers.split(';')[0]
        except:
            signers = None

        positives = report.get('positives')
        trid = report.get('additional_info').get('trid')
        itwUrls = report.get('ITW_urls')
        commRep = report.get('community_reputation')
        scanDate = report.get('scan_date')
        firstSeen = report.get('first_seen')
        lastSeen = report.get('last_seen')
        commentsReport = self.getComments(hash)
        # domainReport = self.getDomainReport('bamba.theplaora.com')
        # ipReport = self.getIpReport('216.157.99.92')
        # urlReport  = self.getUrlReport('http://216.157.99.92/crqg.swf')
        # print json.dumps(domainReport)

        urlJsonReport = []
        domainJsonReport = []
        domains = []
        for itwUrl in itwUrls:
            # print "%s:" % itwUrl
            urlReport = self.getUrlReport(itwUrl)
            if urlReport != None:
                try:
                    if urlReport.get('response_code') == 1:
                        # print "\tPositives:",

                        urlPositives = urlReport.get('positives')
                        # print urlPositives
                        urlAv = urlReport.get('scans')
                        urlJsonAV = []
                        for r in (row for row in urlAv):
                            if urlAv[r]['detected'] == True:
                                # print "\t%s" %r
                                urlJsonAV.append(r)
                        urlJsonReport.append({'url': itwUrl, 'positives': urlPositives, 'urlAV': urlJsonAV})
                except:
                    print("Error retrieving URL report")

            domain = self.process_url(itwUrl)
            if domain not in domains:
                domains.append(domain)
                # domain = "bamba.theplaora.com"
                # print "%s:" % domain
                domainDicReport = {}
                domainReport = self.getDomainReport(domain)
                if domainReport.get('response_code') == 1:
                    domainDicReport.update({'Domain': domain})
                    # print "\tWebutation Domain Info: "
                    webutation = domainReport.get('Webutation domain info')
                    if webutation != None:
                        # print "\t\tSafety Score: ",
                        # print domainReport.get('Webutation domain info').get('Safety score')
                        # print "\t\tVerdict: ",
                        # print domainReport.get('Webutation domain info').get('Verdict')
                        domainDicReport.update({'Webutation domain info': webutation})
                    # print domainDicReport

                    if domainReport.get('categories') != None:
                        domainDicReport.update({'Categories': domainReport.get('categories')})

                    # print "\tUndetected Downloaded Samples: ",
                    if domainReport.get('undetected_downloaded_samples') != None:
                        # print len(domainReport.get('undetected_downloaded_samples'))
                        domainDicReport.update(
                            {'Undetected Downloaded Samples': len(domainReport.get('undetected_downloaded_samples'))})

                    # print "\tDetected Downloaded Samples: ",
                    if domainReport.get('detected_downloaded_samples') != None:
                        # print len(domainReport.get('detected_downloaded_samples'))
                        domainDicReport.update(
                            {'Detected Downloaded Samples': len(domainReport.get('detected_downloaded_samples'))})
                    # print "\tUndetected Samples Communicating to domain: ",
                    if domainReport.get('undetected_communicating_samples') != None:
                        # print len(domainReport.get('undetected_communicating_samples'))
                        domainDicReport.update({'Undetected Communicating Samples': len(
                            domainReport.get('undetected_communicating_samples'))})

                    # print "\tDetected Samples Communicating to domain: ",
                    if domainReport.get('detected_communicating_samples') != None:
                        # print len(domainReport.get('detected_communicating_samples'))
                        domainDicReport.update(
                            {'Detected Communicating Samples': len(domainReport.get('detected_communicating_samples'))})

                    # print "\tDetected Urls: ",
                    if domainReport.get('detected_urls') != None:
                        # print len(domainReport.get('detected_urls'))
                        domainDicReport.update({'Detected Urls': len(domainReport.get('detected_urls'))})

                    # domainJsonReport.append({'Webutation domain info': webutation, 'Websense ThreatSeeker category' : domainReport.get('Websense ThreatSeeker category'), 'Categories' : domainReport.get('categories'), 'Undetected Downloaded Samples': len(domainReport.get('undetected_downloaded_samples')), 'Detected Downloaded Samples': len(domainReport.get('detected_downloaded_samples')), 'Undetected Communicating Samples' : len(domainReport.get('undetected_communicating_samples')), 'Detected Communicating Samples': len(domainReport.get('detected_communicating_samples')), 'Detected Urls' : len(domainReport.get('detected_urls'))})
                    # domainJsonReport.append({'Webutation domain info': webutation, 'Websense ThreatSeeker category' : domainReport.get('Websense ThreatSeeker category')})
                    domainJsonReport.append(domainDicReport)

        report['urlReport'] = urlJsonReport
        report['domainReport'] = domainJsonReport

        similarityReputation = self.similarity(hash)

        report['FileSimilarity'] = similarityReputation

        if signers != None:
            sigRep = self.sigRep(signers)
            report['Signature Reputation'] = self.sigRep(signers)

        if commentsReport.get('response_code') == 1:

            commentsArray = commentsReport.get('comments')
            if commentsArray != []:
                report['Comments'] = commentsArray

        if report.get('additional_info') != None:
            if report.get('additional_info').get('imports') != None:
                imports = report.get('additional_info').get('imports')
                new_imports = {}
                for key, value in imports.items():
                    new_key = key.replace('.', '_')
                    new_imports[new_key] = value

                report['additional_info']['imports'] = new_imports

        return report

    def signer_reputation(self, sig):
        """

        :param sig: signer of a file
        :return:
        """
        baseQuery = 'sigcheck:' + sig
        hashes = self.getHashes(baseQuery, 10)
        sigPositives = {}
        sCount = len(hashes)
        sUndetCount = None
        sPositives = None
        mean = None
        if sCount != 0:
            i = 0
            sUndetCount = 0
            sPositives = []
            for hash in hashes:
                report = self.getfileReport(hash)
                positives = report.get('positives')
                # print positives
                sPositives.append(positives)
                if positives == 0:
                    sUndetCount += 1

                # print similarityPositives
                # print totalScanners
                i += 1
                if i == 10:
                    break
            mean = sum(sPositives) / len(sPositives)
        sigPositives.update({'sPositives': sPositives, 'mean': mean, 'Undetected': sUndetCount, 'sCount': sCount})
        return sigPositives

    def imphashRepScore(self, file):
        """

        :param file:
        :return:
        """

        totalSimImp = 0
        totalSimPositives = 0
        totalSimNegatives = 0
        impRepDetails = {}
        if os.path.isfile(file):
            pe = pefile.PE(file)
            imphash = pe.get_imphash()
            fSize = os.path.getsize(file)
            fSizeUpper = str(fSize + 5000)
            fSizeLower = str(fSize - 5000)

            # Limit the  file size to 5KB+- the reference file.
            baseQuery = 'imphash:' + imphash + ' AND size:' + fSizeUpper + "- AND size:" + fSizeLower + "+"
            hashes = VTUtilsV2.getHashes(baseQuery)
            totalSimImp = len(hashes)
            impRepDetails["imphash"] = imphash
            impRepDetails["totalSamples"] = totalSimImp
            if impRepDetails["totalSamples"] == 0:
                impRepDetails["impRepScore"] = 3
                return impRepDetails

            timeLimit = ""
            if totalSimImp == 300:  # Virustotal returns up to 300 hashes per query
                hashLimit = hashes[
                    299]  # get the last entry. Virustotal sorted results in order of last submission first
                # we get the time as our limiter in our succeeding search.
                fileReport = VTUtilsV2.getfileReport(hashLimit)
                timeLimit = str(fileReport['last_seen'])
                timeLimitString = re.sub("\s+", "T", timeLimit)

            if timeLimit != "":
                query2 = baseQuery + ' AND ls:' + timeLimitString + "+"
            else:
                query2 = baseQuery

            query5 = query2 + ' AND positives:5+'
            query0 = query2 + ' AND positives:0'
            query10 = query2 + ' AND positives:10+'
            query20 = query2 + ' AND positives:20+'
            query30 = query2 + ' AND positives:30+'

            if impRepDetails["totalSamples"] != 0:

                impRepDetails["SimPositives5+"] = len(VTUtilsV2.getHashes(query5))
                impRepDetails["SimPositives10+"] = len(VTUtilsV2.getHashes(query10))
                impRepDetails["SimPositives20+"] = len(VTUtilsV2.getHashes(query20))
                impRepDetails["SimPositives30+"] = len(VTUtilsV2.getHashes(query30))
                impRepDetails["SimPositives0"] = len(VTUtilsV2.getHashes(query0))

                if impRepDetails["SimPositives5+"] / impRepDetails["totalSamples"] >= 0.8 and impRepDetails[
                    "SimPositives0"] == 0:
                    impRepScore = 2

                elif impRepDetails["SimPositives5+"] / impRepDetails["totalSamples"] <= 0.2 and impRepDetails[
                    "SimPositives0"] / impRepDetails["totalSamples"] >= 0.5:
                    impRepScore = 0

                else:
                    impRepScore = 1

                impRepDetails["impRepScore"] = impRepScore
            return impRepDetails


def main():
    parser = argparse.ArgumentParser(description='VT Utility')
    parser.add_argument("-f", "--file", dest="file", help="Submit file to cuckoo")
    parser.add_argument("-s", "--sum", dest="sum", help="Hash input")
    parser.add_argument("--ip", dest="ip", help="IP Address")
    parser.add_argument("--key", dest="api_key", help="VT API Key")
    parser.add_argument("--domain", dest="domain", help="Domain")

    args = parser.parse_args()
    vtUtils = VTUtilsV2(args.api_key)
    file = args.file
    hash = args.sum
    ip = args.ip
    domain = args.domain

    # VTDetails = VTUtilsV2.getVTDetails(hash)

    if domain:
        pprint(VTUtilsV2.getDomainReport(domain))

    if ip:
        pprint(VTUtilsV2.getIPReport(ip))

    if hash:
        pprint(VTUtilsV2.getfileReport(hash))


if __name__ == "__main__":
    main()
