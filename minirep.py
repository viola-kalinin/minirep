# This an interactive script that gathers information about an IP address from various services

import argparse
import json
import os
import re
import requests
from os.path import dirname

def fetch_vt_reputation(address,config):

    headers = {'x-apikey': config['vt_api_key']}
    response = requests.get(url=f"{config['vt_api_url']}/ip_addresses/{address}", headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed VT IP address lookup for {address}. Status code: {response.status_code}. Message: {response.text}")
        return

def parse_whois(vt_rep):
    # Parse the whois string and add to whois_dict
    whois_data = re.split("\r\n|\n",vt_rep['data']['attributes']['whois'])
    if len(whois_data) > 1:
        whois_dict = {}
        for entry in whois_data:
            split = [x.strip() for x in entry.split(':')]
            if len(split) == 2:
                if split[0] not in whois_dict:
                    whois_dict[split[0]] = split[1]
        return whois_dict
    
def main(args):

    # If no address was supplied, prompt
    if not args.Address:
        ip_addr = input("Enter the IP address you would like to check: ")
    else:
        ip_addr = args.Address

    # Load config. Print warning and exit if not found
    try:
        config_file_path = os.path.join(dirname(os.path.realpath(__file__)),"minirep.json")
        print(config_file_path)
        config = json.load(open(config_file_path))
    except Exception as e:
        print(f"Failed to load config file from {config_file_path}.\r\nException: {e}")
        return

    # Query VirusTotal for IP reputation
    if vt_rep := fetch_vt_reputation(ip_addr,config):
        print(f"Reputation Score: {vt_rep['data']['attributes']['reputation']}")
        print(f"Harmless Votes: {vt_rep['data']['attributes']['total_votes']['harmless']}")
        print(f"Malicious Votes: {vt_rep['data']['attributes']['total_votes']['malicious']}")

        
        if whois_dict := parse_whois(vt_rep):
            for key in whois_dict:
                print(f"{key}: {whois_dict[key]}")
    else:
        print(f"Could not obtain reputation data from VirusTotal for {ip_addr}")  
            

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--Address", help ="IP address to scan")
    
    args = parser.parse_args()
    main(args)