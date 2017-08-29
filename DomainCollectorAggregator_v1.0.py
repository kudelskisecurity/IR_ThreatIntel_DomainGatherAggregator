#!/bin/python
"""
Malicious Domain Correlator 

Used to aggregate open-source black listed domains into a single normalized file 

This script comes with the following additional files: 
	'URL-list.txt' = List of all domains regardless of type of block (has all the below types)
	'whiteListDomains.txt' = List of domains to ignore when building the master list

Copyright (c) 2017 Kudelski Security LLC
Author:  David O'Neil  (davidmoneil@gmail.com)
"""
import sys
import re

def processArgs():
	"""
	Used for process all command line aruguments 
	"""
	import argparse
	__author__="David O'Neil - Kudelski Security david.oneil@Kudelskisecurity.com"
	parser = argparse.ArgumentParser(description='This is used to pull down threat indicators (domains) from open source communities. \nInput a list of URLs Format: One per line. \n Each line has should have (Title) , (URL)like:\nmalwaredomainlist,https://www.malwaredomainlist.com/hostslist/hosts.txt ')
	parser.add_argument('-t','--type', help='Used to append the output file with the type of domains list. Example:\nransomeware would produce a ransomeware.results.csv file.',required=False)
	parser.add_argument('-i','--input', help='Enter the list of URLs',required=False)
	parser.add_argument('-p','--path', help='Enter the Path this file should output to.  example:  c:\dns_automation',required=False)
	parser.add_argument('-w','--whitelist', help='Default list is called "Whitelist.txt", or you can manual enter your list.',required=False)
	parser.add_argument('-d','--debug', action='store_true', default=False, help='Enabling Debug will save a copy of each URL results with xxx.results.txt .',required=False)
	args = parser.parse_args()
	return args

def getURL(url):
	"""
	Gets the URL and all data and returns it 
	"""
	import urllib2
	#print 'getting URL: %s' % url
	try:
		req = urllib2.Request(url)
		req.add_header('User-agent', 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36')
		response = urllib2.urlopen(req)
		the_page =  response.read()
	except:
		the_page = 'failed to get data from page. Validate the page in your browser'
	#print 'GetURL Results: %s' % results
	return the_page

def writeDebug(theString,debugResults=False):
	import time
	print theString
	if debugResults:
		outPutFileName = '%s.DNS_Automation_Debug.txt' % (theType)
	 	degbugInfo = open(outPutFileName,'a')
	 	date = time.strftime("%m.%d.%Y")
	 	newResults = '%s,"%s"\n' % (date,theString)
	 	degbugInfo.write(newResults)


def write2File(data,theType=False):
	"""
	Used to write the results to file
	"""
 	import time
 	if theType:
 		outPutFileName = '%s.results.csv' % (theType)
 	else:
	 	outPutFileName = 'results.csv'
 	results = open(outPutFileName,'a')
 	date = time.strftime("%m.%d.%Y")
 	newResults = '%s,"%s","%s"\n' % (date,url,data)
 	results.write(newResults)

def echoMasterList(theSet,FileName,thePath):
	if thePath:
		newPath = '%s\%s_DNS_Automation.txt' % (thePath,FileName.strip())
	else:
		newPath = '%s_DNS_Automation.txt' % FileName.strip()
	results =open(newPath, 'w')
	for item in theSet:
		results.write(item + '\n')
	results.close

def isWhiteListed(theWhiteList,domain):
	results = True
	for item in theWhiteList:
		#print ''
		#print 'checking if: %s  is in: %s' % (item,domain)
		if domain in item:
			results = False
	return results

######## 			Starting the main  		##############
Args = processArgs()

if Args.input:
	urlList = Args.input
else:
	print 'No input selected.  Using the default URL-List.txt file'
	urlList = 'URL-list.txt'

if Args.whitelist:
	whiteList = Args.whiteList
else:
	whiteList = 'WhiteList.txt'

if Args.type:
	theType =  Args.type
else:
	theType = 'All'
debugResults = Args.debug

thePath = Args.path

valid_domain_name_regex = re.compile('(([\da-zA-Z])([\w-]{,62})\.){,127}(([\da-zA-Z])[\w-]{,61})?([\da-zA-Z]\.((xn\-\-[a-zA-Z\d]+)|([a-zA-Z]{2,})))', re.IGNORECASE)

URLS = open(urlList,'r')
#WhiteList = open('WhiteList.txt','r')
with open(whiteList) as f:
	WhiteList = f.readlines()
mastercount = 0
singlecount = 0
masterlist = set()


for url in URLS: # For each url in the file
	if '#' not in url[0:2]:
		name,theURL = url.split(',')
		writeDebug ('',debugResults)
		writeDebug ('################################',debugResults)
		writeDebug ('URL to get data from: %s' % theURL,debugResults)
		results = getURL(theURL) #do a lookup and return string
		if debugResults:
			fileName = '%s.Results.txt' % name
			fileResults = open(fileName,'w')
			for line in results:
				fileResults.write(line)
		results = results.split('\n')
		for row in results:
			if row:
				print row
				if '#' not in row[0:5] or '<' not in row[0:5] or '<url>' in row: #Designed to skip comments 
					addDomain = re.search(r'\b([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\b',row.strip(),re.M|re.I)
					if addDomain:
						theDomain = addDomain.group()
						whitelistExists = isWhiteListed(WhiteList,theDomain) #check to see if it is white listed
						if whitelistExists:
							mastercount = mastercount + 1
							singlecount = singlecount + 1
							masterlist.add(str(theDomain))

		writeDebug ( 'Master Count increased to: %s ' % mastercount,debugResults)
		writeDebug ( 'The Single %s had: %s domains collected' % (name,singlecount),debugResults)
		writeDebug ( 'The Set count = %s' % len(masterlist),debugResults)
		singlecount = 0

echoMasterList(masterlist,theType,thePath)
URLS.close
