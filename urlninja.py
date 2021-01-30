#!/usr/bin/env python3
"""
About:-
Author: sheryar (ninjhacks)
Created on : 22/10/2020
Last Update : 30/01/2021
Program : UrlNinja Plus
Version : 1.2.0
"""
import requests
import os
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from threading import Thread
from optparse import OptionParser
import json

def wayBack(domain):
    if options.subdomain == True:
        domain = "*."+domain
    try:
        rKey =  True
        resumeKey = ""
        while rKey:
            wurl = "http://web.archive.org/cdx/search/cdx?url={}/*&collapse=urlkey&output=json&fl=original,statuscode,mimetype,length{}&showResumeKey=true&limit={}&resumeKey={}".format(domain, wbFilters, WBlimit,resumeKey)
            rep = req.get(wurl, stream=True)
            if rep.status_code == 200:
                if rep.json() != []:
                    if rep.json()[-2] == []:
                        resumeKey = rep.json()[-1][0]
                        for url in rep.json()[1:-2]:
                            print(json.dumps(url))
                    else:
                        rKey = False
                        for url in rep.json()[1:]:
                            print(json.dumps(url))
                else:
                    rKey = False
            else:
                rKey = False
    except requests.RequestException as err:
        if options.verbose:
            print("Error | WayBack | "+str(err))

def commonCrawl(domain):
    if options.subdomain == True:
        domain = "*."+domain
    try:
        rep = req.get(ccIndex+"?url={}/*&output=json&fl=url,status,mime,length{}".format(domain, ccFilters))
        if rep.status_code == 200:
            for url in rep.text.splitlines():
                url = json.loads(url)
                print(json.dumps([url["url"],url["status"],url["mime"],url["length"]]))
    except requests.RequestException as err:
        if options.verbose:
            print("Error | commonCrawl | "+str(err))

def Otx(domain):
    try:
        otxurl = "https://otx.alienvault.com/api/v1/indicators/domain/{}/url_list?limit=0&page=0".format(domain)
        rep = req.get(otxurl)
        if rep.status_code == 200:
            for url in rep.json()["url_list"]:
                if "httpcode" in url:
                    data = [url["url"],str(url["httpcode"]),"",""]
                else:
                    data = [url["url"],"","",""]
                print(json.dumps(data))
    except requests.RequestException as err:
        if options.verbose:
            print("Error | Otx | "+str(err))

def vTotal(domain):
    try:
        vturl = "https://www.virustotal.com/vtapi/v2/domain/report?apikey={}&domain={}".format(vTotalAPI, domain)
        rep = requests.get(vturl)
        if rep.status_code == 200:
            if "detected_urls" in rep.json():
                for url in rep.json()["detected_urls"]:
                    print(json.dumps([url['url'],"","",""]))
            if "undetected_urls" in rep.json():
                for url in rep.json()["undetected_urls"]:
                    print(json.dumps([url[0],"","",""]))
    except requests.RequestException as err:
        if options.verbose:
            print("Error | VirusTotal | "+str(err))

def cCrawlIndex():
    #client = "commonCrawl Index"
    try:
        rep = req.get("http://index.commoncrawl.org/collinfo.json")
        if rep.status_code == 200:
            return rep.json()[0]["cdx-api"]
        else:
            return False
    except:
        return False
    

def worker(domain):
    if cCrawl:
        Thread(target=commonCrawl, args=(domain,)).start()
    if wBack:
        Thread(target=wayBack, args=(domain,)).start()
    if otx:
        Thread(target=Otx, args=(domain,)).start()
    if vtotal:
        Thread(target=vTotal, args=(domain,)).start()

def header():
    os.system('clear')
    title = '''
________________________________________________________________________________                            
_____  __      __________   ______       ________        
__  / / /_________  /__  | / /__(_)____________(_)_____ _
_  / / /__  ___/_  /__   |/ /__  /__  __ \____  /_  __ `/
/ /_/ / _  /   _  / _  /|  / _  / _  / / /___  / / /_/ / 
\____/  /_/    /_/  /_/ |_/  /_/  /_/ /_/___  /  \__,_/  
                                         /___/           
_______________________________________________________________________________

About:-
Author: sheryar (ninjhacks)
Version : 1.1.0
________________________________________________________________________________
    '''
    print ('\033[01;32m' + title + '\033[01;37m')

if __name__ == "__main__":
    parser = OptionParser(usage="%prog: [options]")
    parser.add_option( "-d", dest="domain", help="domain (Example : example.com)")
    parser.add_option( "--sub", dest="subdomain", action='store_true', help="Subdomain (optional)")
    parser.add_option( "-p" , "--providers", dest="providers", default="wayback commoncrawl otx virustotal", help="Select Providers (default : wayback commoncrawl otx virustotal)")
    parser.add_option( "--wbf", dest="wbfilter", default="", help="Set filters on wayback api (Example : statuscode:200 ~mimetype:html ~original:=)")
    parser.add_option( "--ccf", dest="ccfilter", default="", help="Set filters on commoncrawl api (Example : =status:200 ~mime:.*html ~url:.*=)")
    parser.add_option( "--wbl", dest="wbLimit", default=10000, type=int, help="Wayback results per request (default : 10000)")
    parser.add_option( "--otxl", dest="otxLimit", default=10000, type=int, help="Otx results per request (default : 10000)")
    #parser.add_option( "-o", dest="output", help="Output File (optional)")
    parser.add_option( "-r", dest="retry", default=3, type=int, help="Amount of retries for http client	 (default : 3)")
    parser.add_option( "-v", dest="verbose", action='store_false', help="Enable verbose mode to show errors (optional)")
    parser.add_option( "-s", dest="silent", action='store_true', help="Prints only results in the output (optional)")
    parser.add_option( "--ucci", dest="ucci", action='store_true', help="Update CommonCrawl Index (optional)")
    (options, args) = parser.parse_args()

if not options.silent:
    header()

retry_strategy = Retry(
    total=options.retry,
    status_forcelist=[429, 500, 502, 503, 504],
    method_whitelist="GET"
)
adapter = HTTPAdapter(max_retries=retry_strategy)
req = requests.Session()
req.mount("https://", adapter)
req.mount("http://", adapter)
req.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36"
})

wbFilters = ccFilters = ""
cCrawl = wBack = otx = vtotal = False
WBlimit = options.wbLimit 
OTXlimit = options.otxLimit
configFile = open("config.json", "r")
configData = json.load(configFile)
configFile.close()

for provider in options.providers.split():
    if provider == "commoncrawl":
        if options.ucci:
            ccIndex = configData["CommonCrawlIndex"] = cCrawlIndex()
            configFile = open("config.json", "w")
            json.dump(configData, configFile)
            configFile.close()
        else:
            ccIndex = configData["CommonCrawlIndex"]
        if ccIndex != "":
            cCrawl = True
        if options.ccfilter != None:    
            for f in options.ccfilter.split():
                ccFilters = ccFilters+"&filter="+f
    elif provider == "wayback":
        wBack = True
        if options.wbfilter != None:    
            for f in options.wbfilter.split():
                wbFilters = wbFilters+"&filter="+f
    elif provider == "otx":
        otx = True
    elif provider == "virustotal":
        if configData["VirusTotalApi"] != "":
            vTotalAPI = configData["VirusTotalApi"]
            vtotal = True
        else:
            print("Warning | VirusTotal | VirusTotal api not found")

if cCrawl | wBack | otx | vtotal:
    worker(options.domain)