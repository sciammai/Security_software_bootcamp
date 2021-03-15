#!/usr/bin/env python

import requests
import json
import sys
from pathlib import Path
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from pprint import pprint
from datetime import datetime

here = Path(__file__).parent.absolute()
repository_root = (here / ".." ).resolve()
sys.path.insert(0, str(repository_root))

import env

inv_url = env.UMBRELLA.get("inv_url")
inv_token = env.UMBRELLA.get("inv_token")
en_url = env.UMBRELLA.get("en_url")
en_key = env.UMBRELLA.get("en_key")
#Use a domain of your choice
#domain = "internetbadguys.com"
#Ask for the domain
print("Type the domain you want to check:")
domain = input()
#Print a sanitazed URL
san_domain =domain.replace('.' , '(dot)')

#Construct the API request to the Umbrella Investigate API to query for the status of the domain
url = f"{inv_url}/domains/categorization/{domain}?showLabels"
headers = {"Authorization": f'Bearer {inv_token}'}
response = requests.get(url, headers=headers)

#And don't forget to check for errors that may have occured!
response.raise_for_status()

#Make sure the right data in the correct format is chosen, you can use print statements to debug your code
domain_status = response.json()[domain]["status"]

if domain_status == 1:
    print(f"The domain {domain} is found CLEAN")
elif domain_status == -1:
    print(f"The domain {domain} is found MALICIOUS")
elif domain_status == 0:
    print(f"The domain {domain} is found UNDEFINED")

print("This is how the response data from Umbrella Investigate looks like: \n")
pprint(response.json(), indent=4)

#Add another call here, where you check the historical data for either the domain from the intro or your own domain and print it out in a readable format
url = f"{inv_url}/pdns/timeline/{domain}"
headers = {"Authorization": f'Bearer {inv_token}'}
response = requests.get(url, headers=headers).json()

for r in response:
    print("In date" + str(r['date'] + ", the domain " + str(san_domain) + " was mapped to" + str(r['dnsData'][0]['ipData']['startSeen']) ))

#Post the website if it is MALICIOUS
if domain_status == -1:
    url = f"{en_url}events?customerKey={en_key}"
    url_domains = f"{en_url}domains?customerKey={en_key}"
    headers = {"Content-Type" : 'application/json'}
    now = datetime.now().isoformat()
    payload = {
        "alertTime": now + "Z",
        "deviceId": "ba6a59f4-e692-4724-ba36-c28132c761de",
        "deviceVersion": "13.7a",
        "dstDomain": domain,
        "dstUrl": "http://" + domain + "/",
        "eventTime": now + "Z",
        "protocolVersion": "1.0a",
        "providerName": "Security Platform"
    }

    try:
        #Print OLD list of blocked domain
         response_old = requests.get(url_domains, headers=headers)
         response_old.raise_for_status()
         print("The OLD list of blocked domains is:")
         for r in response_old.json()['data']:
             print('- ' + str(r['name']))
         print('*******************************')
         print('Now blocking URL ' + san_domain)
         print('*******************************')
         response = requests.post(url, headers=headers, json=payload)
         response.raise_for_status()
         #Print NEW list of blocked domain
         response_new = requests.get(url_domains, headers=headers)
         response_new.raise_for_status()
         print("The NEW list of blocked domains is:")
         for r in response_new.json()['data']:
             print('- ' + str(r['name']))        
    except Exception as ex:
        print(ex)
