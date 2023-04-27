# This an interactive script that gathers information about an IP address from various services

import argparse
import colorama
import json
import os
import requests
from os.path import dirname
from termcolor import colored,cprint

def fetch_vt_reputation(address,config):

    headers = {'x-apikey': config['vt_api_key']}
    response = requests.get(url=f"{config['vt_api_url']}/ip_addresses/{address}", headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed VT IP address lookup for {address}. Status code: {response.status_code}. Message: {response.text}")
        return
def fetch_abuse_reputation(address,config):
    querystring = {'ipAddress': address,'maxAgeInDays': '30'}
    headers = {'Accept': 'application/json','key': config['ab_api_key']}
    response = requests.request(method = "GET", url=f"{config['ab_api_url']}", headers=headers, params= querystring)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed Abuse IP address lookup for {address}. Status code: {response.status_code}. Message: {response.text}")
        return
def switch (score):
    if score < 30:
        return "PASS"
    elif score <70:
        return "ALLOW"
    else:
        return "BLOCK"
def decision (input):
    if input == "PASS":
        return " is ignored"
    elif input == "ALLLOW":
        return " is being monitored"
    elif input == "BLOCK":
        return " is blocked via firewall"
    else:
        "incorrect option"
def main(args):

    colorama.init()

    # If no address was supplied, prompt
    if not args.Address:
        ip_addr = input("Enter the IP address you would like to check: ")
    else:
        ip_addr = args.Address

    # Load config. Print warning and exit if not found
    try:
        config_file_path = os.path.join(dirname(os.path.realpath(__file__)),"minirep.json")
        config = json.load(open(config_file_path))
    except Exception as e:
        print(f"Failed to load config file from {config_file_path}.\r\nException: {e}")
        return

    # Query VirusTotal for IP reputation. Feel free to discard this section or use it in a different way
    if vt_rep := fetch_vt_reputation(ip_addr,config):
        cprint(colored("""
----------------------------
VIRUS TOTAL REPUTATION DATA
----------------------------""",'green'))
        print(f"Who Is: {vt_rep['data']['attributes']['as_owner']}")
        print(f"Country: {vt_rep['data']['attributes']['country']}")
        print(f"Reputation Score: {vt_rep['data']['attributes']['reputation']}")
        print(f"Harmless Votes: {vt_rep['data']['attributes']['total_votes']['harmless']}")
        print(f"Malicious Votes: {vt_rep['data']['attributes']['total_votes']['malicious']}")
   
   
    
    if ab_rep := fetch_abuse_reputation(ip_addr,config):
        cprint(colored("""
----------------------------
ABUSE IDPD REPUTATION DATA
----------------------------""",'green')) 
        print(f"Abuse Score: {ab_rep['data']['abuseConfidenceScore']}")
        print(f"Usage: {ab_rep['data']['usageType']}")
        print(f"Internet Service Provider: {ab_rep['data']['isp']}")
        print(f"Last Report: {ab_rep['data']['lastReportedAt']}")   

    if (ab_rep := fetch_abuse_reputation(ip_addr,config)) and (vt_rep := fetch_vt_reputation(ip_addr,config)):
        cprint(colored("""
-------------
DECISION TIME
-------------""",'green'))
        print("Based on the data, we recommend the following:")
        print(switch(int(ab_rep['data']['abuseConfidenceScore'])))
        decide = input("Would you like to PASS, ALLOW, or DROP: ")
        print(str(ip_addr) + decision(decide))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--Address", help ="IP address to scan")
    
    args = parser.parse_args()
    main(args)