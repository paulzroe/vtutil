#!/usr/bin/env python
#import pefile
import requests
import json
import os
import re
import sys
import hashlib
from optparse import OptionParser



class VT_UTILS3:
	
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


	def __init__(self, api_key=None):
		if api_key == None:
			raise Exception('Please supply an API KEY') 
		else:
			self.APIKEY = api_key
			requests.packages.urllib3.disable_warnings()

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
	

	def getfileReport(self, hash):
		params = {'apikey':self.APIKEY, 'resource': hash, 'allinfo': 1}		
		for i in range(1,3):
			try:
				response = requests.get(self.VT_REPORT_URL, params=params)				
				return  response.json()		
			except:
				continue
			
		return None
		
	def getfileReport3(self, hash):
		headers = {'x-apikey':self.APIKEY}
		file_uri = self.FILE_URL + hash + '/behaviours'
		for i in range(1,3):
			try:
				response = requests.get(file_uri, headers=headers)			
				return  response.json()		
			except:
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
		except:
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
		
	def getPcapv3(self, hash, sandbox_id, save_file_at):
		headers = {'x-apikey':self.APIKEY}
		pcap_uri = self.PCAP_URL + hash +sandbox_id + '/pcap'
		#print pcap_uri
		response = requests.get(pcap_uri, headers=headers)
		#print response.url
		print response.status_code
		if response.status_code == requests.codes.ok:
			try:
				self.save_downloaded_file(hash + '.pcap', save_file_at, response.content)
			except:
				raise
		return response.status_code
	
	
	
	def vtQuery(self, query, cursor =None):		
		if cursor == None:			
			params = {'query': query, 'limit':300, 'descriptors_only': True}
			
		else:
			params = { 'query': query, 'limit': 300, 'cursor': cursor, 'descriptors_only': True}
			
		headers = {'x-apikey':self.APIKEY}
		response = requests.get(self.SEARCH_URL, headers=headers, params=params)

		try:
			response_json = response.json()			
			return response_json
		except:
			return None

	
	
			
	def getHashesv3(self, query, count = 300):
		hashes = []
		response_json = self.vtQuery(query)		
		proceed = True
		#print json.dumps(response_json)
		try:			
			for data in response_json.get("data"):
				hashes.append(data.get('id'))
			hashcount = len(hashes)
			while hashcount < count:
				if response_json.get('meta').get('cursor') !=None:
					response_json = self.vtQuery(query, cursor = response_json.get('meta').get('cursor'))
					for data in response_json.get("data"):
						hashes.append(data.get('id'))
					hashcount = len(hashes)										
				else:
					return hashes
					
			return hashes
		except:
			return hashes
			
				
		#return hashes

class VT_UTILS:
	
	VT_SEARCH_URL = 'https://www.virustotal.com/vtapi/v2/file/search'
	VT_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
	VT_DOMAIN_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/domain/report'
	VT_URL_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/url/report'
	VT_IP_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
	VT_COMMENTS_URL = 'https://www.virustotal.com/vtapi/v2/comments/get'
	VT_CLUSTERS_URL = 'https://www.virustotal.com/vtapi/v2/file/clusters'
	VT_DOWNLOAD_URL = 'https://www.virustotal.com/vtapi/v2/file/download'
	TRENNER = [".", ":", "-", "~", "@", "!", "/", "_", ";", "[", "]", "(", ")"]

	
	

	CATEGORY = {"Trojan":0,
				"TrojSpy":0,
				"TrojDownloader":0,
				"Backdoor":0,
				"Worm":0,
				"Virus":0,				
				"Tool":0,
				"Riskware":0,
				"Adware":0,
				"Ransomware":0,
				"Exploit":0,
				"PUA":0				
				}
	
				
	AVEXCLUTIONLIST = ['Baidu-International', 
					'NANO-Antivirus', 
					'Zoner', 
					'K7GW', 
					'McAfee-GW-Edition', 
					'TrendMicro-HouseCall',
					'Emsisoft',
					'Ad-Aware']
			
	TRUSTEDAV = ["f_secure",
			"microsoft",
			"eset_nod32",
			"avira",
			"symantec",
			"ikarus",
			"fortinet",
			"gdata",
			"bitdefender",
			"sophos",
			"mcafee",
			"trendmicro",
			"f_prot",
			"panda",
			"ahnlab_v3",
			"malwarebytes",
			"avast",
			"kaspersky",
			"vipre",
			"avg"
			]					
					
	AVLIST = ['bkav',
				'microworld_escan',
				'nprotect',
				'cmc',
				'cat_quickheal',
				'alyac',
				'malwarebytes',
				'vipre',
				'k7antivirus',
				'alibaba',
				'k7gw',
				'thehacker',
				'agnitum',
				'f_prot',
				'symantec',
				'norman',
				'totaldefense',
				'trendmicro_housecall',
				'avast',
				'clamav',
				'kaspersky',
				'bitdefender',
				'nano_antivirus',
				'virobot',
				'aegislab',
				'tencent',
				'ad_aware',
				'emsisoft',
				'comodo',
				'f_secure',
				'drweb',
				'zillya',
				'trendmicro',
				'mcafee_gw_edition',
				'sophos',
				'cyren',
				'jiangmin',
				'avira',
				'antiy_avl',
				'kingsoft',
				'microsoft',
				'superantispyware',
				'ahnlab_v3',
				'gdata',
				'bytehero',
				'mcafee',
				'avware',
				'vba32',
				'panda',
				'zoner',
				'eset_nod32',
				'rising',
				'ikarus',
				'fortinet',
				'avg',
				'baidu_international',
				'qihoo_360'
				]
	
	MAPPING = {" loader":"trojdownloader",
			" risk":"riskware",           
			"adw ":"adware",
			"adware":"adware",
			"backdoor":"backdoor",
			"banker":"trojan",		   
			"bkdr":"backdoor",
			"trj-spy":"trojspy",
			"nfostealer":"trojspy",
			"trojan-spy":"trojspy",
			"trojan.spy":"trojspy",
			"spy ":"trojspy",			
			"spyware":"trojspy",	
			"bundler":"adware",                      
			"dldr":"trojdownloader",
			"down ":"trojdownloader",
			"downware":"trojdownloader",
			"grayware":"riskware",
			" hack":"tool",
			"hackkms":"tool",
			"hacktool":"tool",
			"hktl":"tool",           
			"keygen":"tool",
			"kms":"tool",                     
			"load ":"trojdownloader",
			"lock":"ransomware",
			"filecoder":"ransomware",
			"muldown":"trojdownloader",           
			"ransom":"ransomware",
			"rkit":"rootkit",
			"expl":"exploit",
			"rogue":"riskware",
			"monitor":"tool",
			"risktool":"riskware",
			"rogueware":"riskware",			
			"scareware":"riskware",           
			"sys":"rootkit",
			"trj ":"trojan",
			"troj ":"trojan",
			"unwanted":"pua",
			"pe_": "virus",
			"virus":"virus",
			"pup":"pua",
			"pua":"pua",
			"optional":"pua",
			"not-a-virus":"pua",
			"potentially":"pua",
			"application":"pua",}
	
	REPLACE = [" tool",           
			"application",
			"backdoor",
			"based",
			"behaves",
			"downloader",
			"dropped",
			"dropper",
			"executor",
			"exploit",
			" gen ",
			"generic",
			"generik",
			"genome",
			"heur",
			"heuristic",
			"like",
			"malware",
			"obfuscated",
			"optional",
			"packed",
			"posible",
			"possible",
			"program",
			"ransomware",
			"reputation",
			"riskware",
			"rootkit",
			"suspect",
			"trojan",
			"unclassified",
			"unknown",
			"variant",
			"virus",
			"ware",
			"win32 ",
			"win64",
			"worm",
			"linux",
			"suspicious",
			"msil",
			"html",
			"script",
			"macos",
			"android",
			"java",
			"nsis",
			"troj",
			"other",
			"agent",
			"razy",
			"kazy",
			"zusy",
			"barys",
			"symmi"]
			
			
	KNOWN_ADWARE_LIST = ['graftor', 'dapato', 'dialer', \
					  'addrop', 'egguard', \
					  'cashback', 'diamin', 'midie', \
					  'loadmoney', 'downloadguid', \
					  'advml', 'toptools', 'rukometa', 'eorezo' \
					  'monetizer', 'multi', 'onescan', 'cloud', \
					  'strictor', 'netfilter', 'yantai', 'browsefox', \
					  'downloadadmin', 'somoto', 'ibryte', 'browsefox', \
					  'amonetize', 'installmonster', 'bundlore', 'multiplug', \
					  'installcore', 'opencandy', 'softpulse', 'mypcbackup', \
					  'elex', 'icloader', 'wajam', 'mediamagnet', 'pennybee', \
					  'bundleloader', 'gamevance', 'adsearcher', 'bundlore', \
					  'pullupdate', 'multi', 'crossrider', 'mikey', 'installmonstr', \
					  'dealply', "shedun"]		
					  
	MS_FAMILY_GENERIC = ['skeeyah', 'tiggre', 'dynamer', 'dorv', 'occamy']

	MS_FAMILY_BLACKLIST = ['AndroidOS/LockScreen!rfn']
					


	def __init__(self, api_key=None):
		if api_key == None:
			raise Exception('Please supply an API KEY') 
		else:
			self.APIKEY = api_key
			requests.packages.urllib3.disable_warnings()
	
	def get_combined_cat_family(self, category, family, ms_category, ms_family):
		combined_category, combined_family  = None, None
		
		if ms_category is None and ms_family is None:
			return category, family
			
		else:
			normalized_ms_family = re.split(r'\/|!', ms_family)[1]
			if ms_family in self.MS_FAMILY_BLACKLIST:
				return category, family
			
			elif normalized_ms_family.lower() in self.MS_FAMILY_GENERIC:
				return category, family
			else:
				return ms_category, normalized_ms_family.lower()
			
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
		
		
		for key in sorted(self.MAPPING, key=len, reverse=True):
			names = names.replace(key, self.MAPPING[key])
		
		#print names
		return names	
	
	
	def normalizeMalwareNamesStep2(self, names):
		# sort Replace Map
		self.REPLACE.sort(key=lambda item:(-len(item), item))
		# delete not usable words
		for r in self.REPLACE:
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
	
	
	#def getClassification(jsonData):
	#	if jsonData.get('scans').get('Kaspersky').get('detected') == True:
	#		detection = jsonData.get('scans').get('Kaspersky').get('result')
	#		detectionSplit = detection.split('.')
	#		malware_category = detectionSplit[0]
	#		family = detectionSplit[2]
	#		return malware_category, family
	#	else:
	#		return None
			
	#Thanks to vttool
	"""
	#Deprecated
	def getClassification(self, jsonData):
		malwarenames = []
		family = None
		category = None
		
		scans = self.getRawScans(jsonData)
		for engine, detection in scans.items():		
			if engine in self.TRUSTEDAV:
				if 'Artemis' in detection:
					continue
				malwarenames.append(detection)
				
		if len(malwarenames) == 0:
				return category, family 
		
		names = self.normalizeMalwareNamesStep1(malwarenames)
		#print names
		categoryDict = self.CATEGORY
		for key in categoryDict:
			categoryDict[key] = names.count(key.lower())
		
		#print json.dumps(categoryDict, indent=4, sort_keys=True)
		
		for key in sorted(categoryDict,  key=categoryDict.get, reverse=True):
			category = key
			break 
		#category
		
		names = self.normalizeMalwareNamesStep2(names)
		wordCountMap = self.simpleWordFrequency(names)
		#print wordCountMap
		foundAgent = False
		for key in sorted(wordCountMap,  key=wordCountMap.get, reverse=True):
			count = wordCountMap[key]
			if key == 'agent':
				foundAgent = True
				continue
			elif foundAgent == True and count > 1:
				family = key
				break
				
			elif foundAgent == True and count == 1:
				family = 'agent'
				break
				
			else:
				family = key
				key
			
			family = key
			break
		return category, family	
	"""
	#Added May 10, 2016

	

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
				if engine in self.TRUSTEDAV:
					if engine == 'microsoft':
						microsoft = detection
					if 'Artemis' in detection:
						continue
					malwarenames.append(detection)			
						
			if microsoft is not None:
				#print microsoft
				if ":" in microsoft:
					ms_category, malware_name = microsoft.split(":")
					ms_family = malware_name.split('.')[0]
					#return malware_category, malware_name_no_variant
					
			if len(malwarenames) == 0:
				return category, family, ms_category, ms_family, combined_category, combined_family
			names = self.normalizeMalwareNamesStep1(malwarenames)
			#print names
			categoryDict = self.CATEGORY
			for key in categoryDict:
				categoryDict[key] = names.count(key.lower())
			for key in sorted(categoryDict,  key=categoryDict.get, reverse=True):
				category = key
				break
			
			
			#category			
			names = self.normalizeMalwareNamesStep2(names)
			wordCountMap = self.simpleWordFrequency(names)
			foundAgent = False
			
			#This is just to avoid agent family
			#print wordCountMap
			
			""""
			#deprecated
			for key in sorted(wordCountMap,  key=wordCountMap.get, reverse=True):
				count = wordCountMap[key]
				if key == 'agent':
					foundAgent = True
					continue
				elif foundAgent == True and count > 1:
					if self.isFamilyReadable(key) == True:
						family = key
						break
						
					if len(key) > 5:
						family = key
						break
					if len(key) <=5:
						if self.isFamilyReadable(key) == True:
							family = key
						else:
							family = 'agent'
					else:
						family = 'agent'
					
					
					break
					
				elif foundAgent == True and count == 1:
					family = 'agent'
					break
					
				else:
					family = key
	
				break		
			
			"""

			for key in sorted(wordCountMap,  key=wordCountMap.get, reverse=True):
				count = wordCountMap[key]
				
				if count > 2:
					family = key
					break
				if len(key) > 7:
					family = key
					break
				if self.isFamilyReadable(key) == True:
					family = key
					break
					
			
			#if category == 'Trojan' or category == 'Riskware' or category == 'PUA' or category == 'Ransomware':
			if family in self.KNOWN_ADWARE_LIST:
				category = 'Adware'
	
			#Try fix invalid family names
			if family is not None:
				if len(family) <5:
					if self.isFamilyReadable(family) == False:
						family = 'unknown'
						
			if category is not None and family is None:
				family = "generic"
				
			
			combined_category, combined_family  = self.get_combined_cat_family(category, family, ms_category, ms_family)
			
			return category, family, ms_category, ms_family, combined_category, combined_family
	
	def getScans(self, jsonData):
		scans = {}		
		if 'scans' in jsonData:
			for engine, signature in jsonData.get("scans").items():
				if signature['detected']:
					avEngine_ = engine.lower()
					avEngine = re.sub(r'[\+-]', "_", avEngine_)
					if avEngine in self.AVLIST:						
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
		try:
			with open(myfile,'rb') as f:
				for chunk in iter(lambda: f.read(8192), ''):
					sha1.update(chunk)
					md5.update(chunk)
			f.close()			
			return sha1.hexdigest(), md5.hexdigest()
	
		except Exception, detail:
			print myfile, detail
			return 'Error', myfile
	
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
			except:
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
		except:
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
		

	
	def getVTDetails(self, hash):
		report =  self.getfileReport(hash)
	
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
		#domainReport = self.getDomainReport('bamba.theplaora.com')
		#ipReport = self.getIpReport('216.157.99.92')
		#urlReport  = self.getUrlReport('http://216.157.99.92/crqg.swf')
		#print json.dumps(domainReport)
		

			
		urlJsonReport = []
		domainJsonReport =[]
		domains=[]
		for itwUrl in itwUrls:
			#print "%s:" % itwUrl			
			urlReport  = self.getUrlReport(itwUrl)
			if urlReport !=None:
				try:
					if urlReport.get('response_code') == 1:
						#print "\tPositives:",
						
						urlPositives = urlReport.get('positives')
						#print urlPositives
						urlAv = urlReport.get('scans')
						urlJsonAV =  []
						for r in (row for row in urlAv):
							if urlAv[r]['detected'] == True:
								#print "\t%s" %r
								urlJsonAV.append(r)
						urlJsonReport.append({'url' : itwUrl, 'positives' : urlPositives, 'urlAV' : urlJsonAV})
				except:
					print "Error retrieving URL report"
		
						
			
			domain = self.process_url(itwUrl)
			if domain not in domains:
				domains.append(domain)
				#domain = "bamba.theplaora.com"
				#print "%s:" % domain
				domainDicReport ={}
				domainReport = self.getDomainReport(domain)
				if domainReport.get('response_code') == 1:
					domainDicReport.update({'Domain' : domain})
					#print "\tWebutation Domain Info: "
					webutation = domainReport.get('Webutation domain info')
					if webutation != None:				
						#print "\t\tSafety Score: ",
						#print domainReport.get('Webutation domain info').get('Safety score')
						#print "\t\tVerdict: ",
						#print domainReport.get('Webutation domain info').get('Verdict')
						domainDicReport.update({'Webutation domain info': webutation})
						#print domainDicReport
											
					
					if domainReport.get('categories') != None:
						domainDicReport.update({'Categories': domainReport.get('categories')})
						
						
						
					#print "\tUndetected Downloaded Samples: ",
					if domainReport.get('undetected_downloaded_samples') != None:
						#print len(domainReport.get('undetected_downloaded_samples'))
						domainDicReport.update({'Undetected Downloaded Samples': len(domainReport.get('undetected_downloaded_samples'))})
						
					#print "\tDetected Downloaded Samples: ",
					if domainReport.get('detected_downloaded_samples') != None:
						#print len(domainReport.get('detected_downloaded_samples'))
						domainDicReport.update({'Detected Downloaded Samples': len(domainReport.get('detected_downloaded_samples'))})
					#print "\tUndetected Samples Communicating to domain: ",
					if domainReport.get('undetected_communicating_samples') != None:
						#print len(domainReport.get('undetected_communicating_samples'))						
						domainDicReport.update({'Undetected Communicating Samples': len(domainReport.get('undetected_communicating_samples'))})

					
					#print "\tDetected Samples Communicating to domain: ",				
					if domainReport.get('detected_communicating_samples') != None:
						#print len(domainReport.get('detected_communicating_samples'))
						domainDicReport.update({'Detected Communicating Samples': len(domainReport.get('detected_communicating_samples'))})

					#print "\tDetected Urls: ",
					if domainReport.get('detected_urls') != None:
						#print len(domainReport.get('detected_urls'))
						domainDicReport.update({'Detected Urls': len(domainReport.get('detected_urls'))})

					#domainJsonReport.append({'Webutation domain info': webutation, 'Websense ThreatSeeker category' : domainReport.get('Websense ThreatSeeker category'), 'Categories' : domainReport.get('categories'), 'Undetected Downloaded Samples': len(domainReport.get('undetected_downloaded_samples')), 'Detected Downloaded Samples': len(domainReport.get('detected_downloaded_samples')), 'Undetected Communicating Samples' : len(domainReport.get('undetected_communicating_samples')), 'Detected Communicating Samples': len(domainReport.get('detected_communicating_samples')), 'Detected Urls' : len(domainReport.get('detected_urls'))})
					#domainJsonReport.append({'Webutation domain info': webutation, 'Websense ThreatSeeker category' : domainReport.get('Websense ThreatSeeker category')})
					domainJsonReport.append(domainDicReport)
		#domain
			#undetected_downloaded_samples - get count
			#detected_downloaded_samples - get count and mean
			#BitDefender domain info:
			#Websense ThreatSeeker category
			#Webutation domain info
				#Safety score
				#Verdict
			#detected_communicating_samples - get count and mean
			#undetected_communicating_samples -  get count
			#categories
		#url
			#AV = urlReport["scans"]
			#for r in (row for row in AV):
			#	if AV[r]["detected"] == 1:
			#		print AV[r]
			
			
		#rint urlJsonReport
		#print domainJsonReport
		#domainJsonReport.append(domainDicReport)
		report['urlReport'] = urlJsonReport
		report['domainReport'] = domainJsonReport
		
		
		
		similarityReputation = self.similarity(hash)
		#print similarityReputation
		report['FileSimilarity'] = similarityReputation
		
		
		#print "Similarity Reputation:",
		#print similarityReputation
		
		if signers != None:
			#print "Signers: ",
			#print signers
			sigRep = self.sigRep(signers)
			#print "Signature Reputation: ",
			#print sigRep			
			report['Signature Reputation'] = self.sigRep(signers)

		#print domainReport		
		#print "Magic: %s" % magicFileType
		#print "Publisher: %s " % publisher
		#print "Trid: %s" % trid
		#print "Submission Names: %s " % submissionNames
		#print "ITWurls: %s " % itwUrls
		#print "Community Reputation: %s" %commRep
		#print "Scan Date: %s" % scanDate
		#print "First Seen: %s " %firstSeen
		#print "Last Seen: %s" %lastSeen
		if commentsReport.get('response_code') == 1:
			#print "Comments:"
			commentsArray = commentsReport.get('comments')
			if commentsArray != []:
				report['Comments'] = commentsArray
				#for comment in commentsArray:
					#print "\t%s" % comment.get('comment')
					
					
		if report.get('additional_info') != None:
			if report.get('additional_info').get('imports') != None:
				imports = report.get('additional_info').get('imports')
				new_imports = {}
				for key, value in imports.items():
					new_key = key.replace('.', '_')
					new_imports[new_key] = value
				
				report['additional_info']['imports'] = new_imports 
			
		
		#print json.dumps(report)
		return report
		
			
		
	
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
	
	VTDetails = vtUtils.getVTDetails(hash)
	
	



if __name__ == "__main__":
	main()
