#!/usr/bin/env python

import requests
import env

# Verify Umbrella access
inv_token = env.UMBRELLA.get("inv_token")
inv_url = env.UMBRELLA.get("inv_url")
en_url = env.UMBRELLA.get("en_url")
en_key = env.UMBRELLA.get("en_key")

if not inv_token:
    print("ERROR: environment variable \'INVESTIGATE_TOKEN\' not set.")
    sys.exit(1)
elif not en_key:
    print ("ERROR: environment variable \'ENFORCEMENT_KEY\' not set.")

headers = {'Authorization': 'Bearer ' + inv_token}
resp_inv = requests.get(f'{inv_url}/domains/categorization/amazon.com', headers=headers)

if resp_inv.status_code == 200:
    print("Umbrella Investigate Access verified")
else:
    print(f"Investigate status code: {resp_inv.status_code}")

resp_en = requests.get(f'{en_url}/domains?customerKey={en_key}')

if resp_en.status_code == 200:
    print("Umbrella Enforcement Access verified")
else:
    print(f"Enforcement status code: {resp_en.status_code}")

#Verify AMP access

amp_host = env.AMP.get("host")
amp_client_id = env.AMP.get("client_id")
amp_api_key = env.AMP.get("api_key")

resp_amp = requests.get(f"https://{amp_client_id}:{amp_api_key}@{amp_host}/v1/event_types")

if resp_amp.status_code == 200:
    print("AMP Access verified")
else:
    print(f"AMP status code: {resp_amp.status_code}")

#Verify TG access
tg_sha = "b1380fd95bc5c0729738dcda2696aa0a7c6ee97a93d992931ce717a0df523967"

tg_host = env.THREATGRID.get("host")
tg_api_key = env.THREATGRID.get("api_key")

resp_tg = requests.get(f"https://{tg_host}/api/v2/search/submissions?q={tg_sha}&api_key={tg_api_key}")

if resp_tg.status_code == 200:
    print("Threat Grid Access verified")
else:
    print(f"Threat Grid status code: {resp_tg.status_code}")

#Verify CTR access
ctr_host = env.THREATRESPONSE.get("ctr_host")
ctr_client_id = env.THREATRESPONSE.get("ctr_client_id")
ctr_client_pwd = env.THREATRESPONSE.get("ctr_client_pwd")

headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json'
    }

resp_ctr = requests.post(f"https://{ctr_host}/iroh/oauth2/token", headers=headers, auth=(ctr_client_id, ctr_client_pwd), data='grant_type=client_credentials')

if resp_ctr.status_code == 200:
    print("Threat Response Access verified")
else:
    print(f"Threat Response status code: {resp_ctr.status_code}")