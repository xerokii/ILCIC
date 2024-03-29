"""
-----------------------------------
  _____   _         _____   _____    _____ 
 |_   _| | |       / ____| |_   _|  / ____|
   | |   | |      | |        | |   | |     
   | |   | |      | |        | |   | |     
  _| |_  | |____  | |____   _| |_  | |____ 
 |_____| |______|  \_____| |_____|  \_____|

----------------------------------
IP List Compromise Indicator Comprobation

Script to check compromise indicator from a IP list in csv.

v2.2

The input csv must be defined in "file" variable
The output must be defined in script call.
"""
import csv
import urllib3
import requests
import json
from csv import DictReader

#Disabling warning certificied
urllib3.disable_warnings()

file = <INPUT_FILE>
#Printing headers
print('Address,','domain,','ISP,','Country,','ScoreVT,','ScoreABDIP,','ReportsABDIP,','Events')
#Open CSV and read every row.
with open (file,'r') as file_csv:
    read_csv = DictReader(file_csv)
    for row in read_csv:

    # Defining the api-endpoint AbuseDBIP
        urladb = 'https://api.abuseipdb.com/api/v2/check'
        querystringadb = {
            'ipAddress': row['IP'],
            'maxAgeInDays': '365'
        }
        headersadb = {
            'Accept': 'application/json',
            'Key': <ABUSEDBIP_APIKEY>
        }
        responseadb = requests.request(method='GET', url=urladb, headers=headersadb, params=querystringadb,verify=False)

    #Defining the api-endpoint VirusTotal
        urlvt = "https://www.virustotal.com/api/v3/ip_addresses/"+row['IP']
        headersvt = {
            "Accept": "application/json",
            "x-apikey": <VT_APIKEY>
        }
        responsevt = requests.request("GET", urlvt, headers=headersvt)

    #Difining the api-endpoint IBM-Xforce
        urlxforce="https://api.xforce.ibmcloud.com/api/ipr/"+row['IP']
        headersxforce = {
            'Accept': 'application/json',
            'Authorization' : <XFORCE_APIKEY>
        }
        responsexforce = requests.request("GET", url=urlxforce, headers=headersxforce)

        # Formatted output
        decodedResponseadb = json.loads(responseadb.text)
        decodeResponsevt = json.loads(responsevt.text)
        decodeResponsexforce = json.loads(responsexforce.text)

        #Extract data from json
        domain = decodedResponseadb['data']['domain']
        address = decodedResponseadb['data']['ipAddress']
        country = decodedResponseadb['data']['countryCode']
        scoreadb = decodedResponseadb['data']['abuseConfidenceScore']
        scorevt = decodeResponsevt['data']['attributes']['last_analysis_stats']['malicious']
        isp = decodedResponseadb['data']['isp']
        reportsadb = decodedResponseadb['data']['totalReports']
        scorexforce = decodeResponsexforce['score']
        categoryxforce = decodeResponsexforce['categoryDescriptions']
        
        #Print all data
        print(address,domain,isp,country,scorevt,scoreadb,reportsadb,scorexforce,categoryxforce,row['Events'],sep=",")
        