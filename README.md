# minirep
This repository is used for the ISP-452 Threat Intelligence Lab. Your goal will be to extend the functionality of the tool to incorporate additional services:

Further enrich the data with another service. Examples of services with free API access tiers are below (pick one or two):
* GreyNoise
* Shodan
* Abuse IPDB
* ARIN
* SecurityTrails
* Emerging Threats (TXT file access)
* Threat Jammer (https://threatjammer.com/docs/threat-jammer-api-keys)

# Prerequisites
1. Python 3.8+
2. VirusTotal API Key

# Installation (Windows)
1. Launch PowerShell
2. Clone the repository: `git clone https://github.com/rabchapman/minirep.git`
3. Change directories into the repository folder: `cd minirep`
4. Create the virtual environment: `python -m venv .`
5. Activate the virtual environment: `.\Scripts\activate`
6. Install the required packages: `pip3 install -r requirements.txt`
7. Create the config file (Add your API Key): `@{"vt_api_key"="YOUR_API_KEY_HERE";"vt_api_url"="https://www.virustotal.com/api/v3"} | ConvertTo-Json | Out-File .\minirep.json`
8. Run minirep.py: `python3 minirep.py`


# Analysis
Based on the data you gather, render a verdict of either `DENY`, `ALERT`, `PASS`. 
* Denied IPs should be blocked from ingress/egress on your network. 
* Alerting IPs should be monitored for further activity. These will be subject to further inspection for a definitive verdict
* Passed IPs will be ignored

# Outcomes
- Interact with API services programatically
- Understand IP reputation services and how they can assist with making decisions to protect your network
- Understand the limitations of these services (e.g. true & false positives, transience of IPs, etc.)