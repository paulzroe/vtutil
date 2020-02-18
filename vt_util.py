#!/usr/bin/env python
#import pefile
import requests
import json
import os
import re
import sys
import hashlib
import variables as v
from optparse import OptionParser


class VT_UTILS:
	
	VT_SEARCH_URL = 'https://www.virustotal.com/vtapi/v2/file/search'
	VT_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
	VT_DOMAIN_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/domain/report'
	VT_URL_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/url/report'
	VT_IP_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
	VT_COMMENTS_URL = 'https://www.virustotal.com/vtapi/v2/comments/get'
	VT_CLUSTERS_URL = 'https://www.virustotal.com/vtapi/v2/file/clusters'
	VT_DOWNLOAD_URL = 'https://www.virustotal.com/vtapi/v2/file/download'
	PCAP_URL = 'https://www.virustotal.com/api/v3/file_behaviours/'
	FILE_URL = 'https://www.virustotal.com/api/v3/files/'
	SEARCH_URL = 'https://www.virustotal.com/api/v3/intelligence/search'	
	TRENNER = [".", ":", "-", "~", "@", "!", "/", "_", ";", "[", "]", "(", ")"]

				

	def __init__(self, api_key=None, verbose=False):
		if api_key == None:
			raise Exception('Please supply an API KEY') 
		else:
			self.APIKEY = api_key
			requests.packages.urllib3.disable_warnings()
			self.verbose = verbose
	
	def get_combined_cat_family(self, category, family, ms_category, ms_family):
		combined_category, combined_family  = None, None
		
		if ms_category is None and ms_family is None:
			return category, family
			
		else:
			
			if ms_family in v.MS_FAMILY_BLACKLIST:
				return category, family
			
			elif ms_family.lower() in v.MS_FAMILY_GENERIC:
				return category, family
			else:
				return ms_category, ms_family.lower()
			
	def isFamilyReadable(self, family):
		VOWELS = "aeiou"
		PHONES = ['sh', 'ch', 'ph', 'sz', 'cz', 'sch', 'rz', 'dz']
		if family:
			consecutiveVowels = 0
			consecutiveConsonents = 0
			for idx, letter in enumerate(family.lower()):
				vowel = True if letter in VOWELS else False
		
				if idx:
					prev = family[idx-1]               
					prevVowel = True if prev in VOWELS else False
					if not vowel and letter == 'y' and not prevVowel:
						vowel = True
		
					if prevVowel != vowel:
						consecutiveVowels = 0
						consecutiveConsonents = 0
		
				if vowel:
					consecutiveVowels += 1
				else:
					consecutiveConsonents +=1
		
				if consecutiveVowels >= 3 or consecutiveConsonents > 3:
					return False
		
				if consecutiveConsonents == 3:
					subStr = family[idx-2:idx+1]
					if any(phone in subStr for phone in PHONES):
						consecutiveConsonents -= 1
						continue    
					return False                
		
		return True
			
	def save_downloaded_file(self, filename, save_file_at, file_stream):
		""" Save Downloaded File to Disk Helper Function
		:param save_file_at: Path of where to save the file.
		:param file_stream: File stream
		:param filename: Name to save the file.
		"""
		filename = os.path.join(save_file_at, filename)
		with open(filename, 'wb') as f:
			f.write(file_stream)
			f.flush()
	
			
			
	def get_VTfile(self, file_hash, save_file_at):
		""" Get the scan results for a file.
		Even if you do not have a Private Mass API key that you can use, you can still download files from the
		VirusTotal storage making use of your VirusTotal Intelligence quota, i.e. programmatic downloads will
		also deduct quota.
		:param file_hash: You may use either the md5, sha1 or sha256 hash of the file in order to download it.
		:param save_file_at: Path of where to save the file.
		"""		
		params = {'apikey':self.APIKEY, 'hash': file_hash}
		
		try:
			response = requests.get(self.VT_DOWNLOAD_URL, params=params)			
		except requests.RequestException as e:
			return dict(error=e.message)
	
		if response.status_code == requests.codes.ok:
			try:
				self.save_downloaded_file(file_hash, save_file_at, response.content)
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
			
			
			
	def normalizeMalwareNamesStep1(self, malwarenames):
		# malwarenames-list to string
		names = " ".join(malwarenames)
		#print names
		for trn in self.TRENNER:
			names = names.replace(trn, " ").lower()
		
		
		for key in sorted(v.MAPPING, key=len, reverse=True):
			names = names.replace(key, v.MAPPING[key])
		
		#print names
		return names	
	
	
	def normalizeMalwareNamesStep2(self, names):
		# sort Replace Map
		v.REPLACE.sort(key=lambda item:(-len(item), item))
		# delete not usable words
		for r in v.REPLACE:
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
		
		#print tmpNames
		return tmpNames
	
		
	def simpleWordFrequency(self, tmpNames):
		# find the most frequently occuring words
		wordCount = {}
		for wort in tmpNames:
			w = wort.strip()
			if len(w) > 0:
				wordCount[w] = wordCount.get(w, 0) + 1
		
		return wordCount
		
		
	def getFileType(self, jsonData):
		if jsonData.get('type') == 'unknown':
			trid = jsonData.get('additional_info').get('trid')
			if trid is None:
				return jsonData.get('type')
			if "Disk Image (Macintosh)" in trid:
				return "MAC DMG"
		
		return jsonData.get('type')
	

	

	def getClassification(self, jsonData):
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
								"ms_family": ms_family,
								"ms_category": ms_category,
								"suggested_category": combined_category,
								"suggested_family": combined_family
							}
			
			scans = self.getRawScans(jsonData)
			for engine, detection in scans.items():		
				if engine in v.TRUSTEDAV:
					if 'Artemis' in detection:
						continue
					malwarenames.append(detection)
			
			malwarebytes = scans.get('malwarebytes')
			microsoft = scans.get('microsoft')
			
			if malwarebytes:
				malwarebytes_split = malwarebytes.split(".")
				ms_category  = malwarebytes_split[0]
				ms_family = "_".join(malwarebytes_split[1:]).lower()
				
				
				
				if "malpack" in ms_family or "agent" in ms_family or ms_family=='bot':
					malwarebytes = None
				
			if microsoft and malwarebytes is None:
				#print microsoft
				if ":" in microsoft:
					ms_category, malware_name = microsoft.split(":")
					ms_family = malware_name.split('.')[0]
					normalized_ms_family = re.split(r'\/|!', ms_family)[1]
					ms_family = normalized_ms_family.lower()
					#return malware_category, malware_name_no_variant
					
			if len(malwarenames) == 0:
			
				classification = {"family": family,
								"category": category,
								"ms_family": ms_family,
								"ms_category": ms_category,
								"suggested_category": combined_category,
								"suggested_family": combined_family
							}
				return classification
			names = self.normalizeMalwareNamesStep1(malwarenames)
			#print names
			categoryDict = v.CATEGORY
			for key in categoryDict:
				categoryDict[key] = names.count(key.lower())
			for key in sorted(categoryDict,  key=categoryDict.get, reverse=True):
				category = key
				break
			
			
			#category			
			names = self.normalizeMalwareNamesStep2(names)
			wordCountMap = self.simpleWordFrequency(names)
			foundAgent = False
			
			for key in sorted(wordCountMap,  key=wordCountMap.get, reverse=True):
				count = wordCountMap[key]
				
				
				#first priority, if this family occured more thatn 2 times
				if count > 2:
					family = key
					break
				#if occured 2 times or less, choose the one that has length greater than 7
				if len(key) > 7:
					family = key
					break
					
				#if occured 2 times or less, check if the family is readable
				if self.isFamilyReadable(key) == True:
					family = key
					break
					
			
			#if category == 'Trojan' or category == 'Riskware' or category == 'PUA' or category == 'Ransomware':
			if family in v.KNOWN_ADWARE_LIST:
				category = 'Adware'
	
			#Try fix invalid family names
			if family is not None:
				if len(family) <5:
					if self.isFamilyReadable(family) == False:
						family = 'unknown'
						
			if category is not None and family is None:
				family = "generic"
				
			
			combined_category, combined_family  = self.get_combined_cat_family(category, family, ms_category, ms_family)
			classification = {"family": family,
								"category": category,
								"ms_family": ms_family,
								"ms_category": ms_category,
								"suggested_category": combined_category,
								"suggested_family": combined_family
							}
			
			return classification
	
	def getScans(self, jsonData):
		scans = {}		
		if 'scans' in jsonData:
			for engine, signature in jsonData.get("scans").items():
				if signature['detected']:
					avEngine_ = engine.lower()
					avEngine = re.sub(r'[\+-]', "_", avEngine_)
					if avEngine in v.AVLIST:						
						scans[avEngine] = signature['result']
		
		return scans

	def getRawScans(self, jsonData):
		scans = {}		
		if 'scans' in jsonData:
			for engine, signature in jsonData.get("scans").items():
				if signature['detected']:
					avEngine_ = engine.lower()
					avEngine = re.sub(r'[\+-]', "_", avEngine_)
					scans[avEngine] = signature['result']
		
		return scans		
		
	def hash_for_file(self, myfile):
		sha1 = hashlib.sha1()
		md5 = hashlib.md5()
		sha256 = hashlib.sha256()
		
		try:
			with open(myfile,'rb') as f:
				for chunk in iter(lambda: f.read(8192), ''):
					sha1.update(chunk)
					md5.update(chunk)
					sha256.update(chunk)
			f.close()			
			hashes = {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}
			return hashes
	
		except Exception as e:
			
			if args.verbose:
			
				print(repr(e))
				
			hashes = {"md5": None, "sha1": None, "sha256": None}
			return hashes
	
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
			



	def vtQuery(self, query, offset =None):		
		if offset == None:			
			params = {'apikey':self.APIKEY, 'query': query}
			
		else:
			params = {'apikey':self.APIKEY, 'query': query, 'offset': offset}
		response = requests.get(self.VT_SEARCH_URL, params=params)

		try:
			response_json = response.json()			
			return response_json
		except:
			return None

	def vtClusters(self, query, offset =None):		
		if offset == None:
			params = {'apikey':self.APIKEY, 'query': query}
		else:
			params = {'apikey':self.APIKEY, 'query': query, 'offset': offset}
		response = requests.get(self.VT_SEARCH_URL, params=params)
		try:
			response_json = response.json()
			return response_json
		except:
			return None
			
	def getHashes(self, query, count = 300):
		hashes = []
		response_json = self.vtQuery(query)		
		proceed = True
		
		try:			
			hashes  =  response_json["hashes"]
			
			hashcount = len(hashes)
			while hashcount < count:
				if response_json.get('offset') !=None:
					response_json = self.vtQuery(query, offset = response_json.get('offset'))
					hashes.extend(response_json.get('hashes'))
					hashcount = len(hashes)										
				else:
					return hashes
					
			return hashes
		except:
			return hashes
			
		#return hashes


	def getfileReport(self, hash):
		params = {'apikey':self.APIKEY, 'resource': hash, 'allinfo': 1}		
		for i in range(1,3):
			try:
				response = requests.get(self.VT_REPORT_URL, params=params)				
				return  response.json()		
			except Exception as e:
				if self.verbose:
					print(repr(e))
				continue
			
		return None

	def getDomainReport(self, domain):
		params = {'domain': domain, 'apikey':self.APIKEY, 'allinfo': 1}
		response = requests.get(self.VT_DOMAIN_REPORT_URL, params=params)
		response_json = response.json()		
		return response_json		
	

	def getUrlReport(self, url):
		params = {'resource': url, 'apikey':self.APIKEY, 'allinfo': 1}		
		response = requests.get(self.VT_URL_REPORT_URL, params=params)		
		try:
			response_json = response.json()						
		except Exception as e:
			if self.verbose:
				print(repr(e))
			response_json = None
		return response_json
		
		

	def getIpReport(self, url):
		params = {'ip': url, 'apikey':self.APIKEY}
		response = requests.get(self.VT_IP_REPORT_URL, params=params)
		response_json = response.json()		
		return response_json			


	def getComments(self, hash):
		params = {'apikey':self.APIKEY, 'resource': hash, 'allinfo': 1}
		response = requests.get(self.VT_COMMENTS_URL, params=params)
		response_json = response.json()		
		return response_json


		
		
	def getfileBehaviorV3(self, hash):
		headers = {'x-apikey':self.APIKEY}
		file_uri = self.FILE_URL + hash + '/behaviours'
		for i in range(1,3):
			try:
				response = requests.get(file_uri, headers=headers)			
				return  response.json()		
			except Exception as e:
				if self.verbose:
					print(repr(e))
				continue
			
		return None
		
		
	def getfileReportV3(self, hash):
		headers = {'x-apikey':self.APIKEY}
		file_uri = self.FILE_URL + hash
		for i in range(1,3):
			try:
				response = requests.get(file_uri, headers=headers)			
				return  response.json()
				
			except Exception as e:
				if self.verbose:
					print(repr(e))
				continue
			
		return None
		
			
	def getPcapV3(self, hash, sandbox_id, save_file_at):
		headers = {'x-apikey':self.APIKEY}
		pcap_uri = self.PCAP_URL + hash +sandbox_id + '/pcap'
		#print pcap_uri
		response = requests.get(pcap_uri, headers=headers)
		#print response.url
		
		if args.verbose:
			print (response.status_code)
		if response.status_code == requests.codes.ok:
			try:
				self.save_downloaded_file(hash + '.pcap', save_file_at, response.content)
			except Exception as e:
				if self.verbose:
					print(repr(e))
				raise
		return response.status_code
	
	
	
	def vtQueryV3(self, query, cursor =None):		
		if cursor == None:			
			params = {'query': query, 'limit':300, 'descriptors_only': True}
			
		else:
			params = { 'query': query, 'limit': 300, 'cursor': cursor, 'descriptors_only': True}
			
		headers = {'x-apikey':self.APIKEY}
		response = requests.get(self.SEARCH_URL, headers=headers, params=params)

		try:
			response_json = response.json()			
			return response_json
			
		except Exception as e:
			if self.verbose:
				print(repr(e))
			return None

	
	
			
	def getHashesV3(self, query, count = 300):
		#returns a list of hashes
		#Query:
		hashes = []
		response_json = self.vtQueryV3(query)		
		proceed = True
		try:			
			for data in response_json.get("data"):
				hashes.append(data.get('id'))
			hashcount = len(hashes)
			while hashcount < count:
				if response_json.get('meta').get('cursor') !=None:
					response_json = self.vtQueryV3(query, cursor = response_json.get('meta').get('cursor'))
					for data in response_json.get("data"):
						hashes.append(data.get('id'))
					hashcount = len(hashes)										
				else:
					return hashes
					
			return hashes
		except Exception as e:
			if self.verbose:
				print(repr(e))
			return hashes
		
	
	def similarity(self, hash):
		baseQuery = 'similar-to:' + hash
		hashes = self.getHashes(baseQuery, 10)
		similarityPositives =  {}
		sCount = len(hashes)
		sUndetCount = None
		sPositives = None
		mean = None
		if sCount != 0:
			i = 0					
			sUndetCount = 0
			sPositives = []
			
			for hash in hashes:
				report =  self.getfileReport(hash)
				positives = report.get('positives')
				if positives == None:
					continue
				#print positives
				sPositives.append(positives)
				if positives == 0:
					sUndetCount += 1
				#print similarityPositives			
				#print totalScanners
				i+=1
				if i==10:
					break	
			
			mean = sum(sPositives)/len(sPositives)
		similarityPositives.update({'sPositives' : sPositives, 'mean' : mean, 'Undetected' : sUndetCount, 'sCount' : sCount})
		return similarityPositives
	
	def sigRep(self, sig):
		baseQuery = 'sigcheck:' + sig
		hashes = self.getHashes(baseQuery, 10)
		sigPositives =  {}
		sCount = len(hashes)
		sUndetCount = None
		sPositives = None
		mean = None
		if sCount != 0:
			i = 0	
			sUndetCount = 0
			sPositives = []			
			for hash in hashes:
				report =  self.getfileReport(hash)
				positives = report.get('positives')
				#print positives
				sPositives.append(positives)
				if positives == 0:
					sUndetCount += 1

				#print similarityPositives			
				#print totalScanners
				i+=1
				if i==10:
					break
			mean = sum(sPositives)/len(sPositives)
		sigPositives.update({'sPositives' : sPositives, 'mean' : mean, 'Undetected' : sUndetCount, 'sCount' : sCount})
		return sigPositives	
		
			
		
def main():


	vtUtils = VT_UTILS()

	parser = OptionParser()
	
	parser.add_option("-f", "--file", dest="file",   help="Submit file to cuckoo")	
	parser.add_option("-s", "--sum", dest="sum", help="Hash input")
	(options, args) = parser.parse_args()    
	
	file = options.file
	hash =  options.sum
	
	
	



if __name__ == "__main__":
	main()

