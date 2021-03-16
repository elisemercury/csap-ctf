#!/usr/bin/env python

import requests
import json
import sys
from pathlib import Path
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from pprint import pprint
from webexteamssdk import WebexTeamsAPI

here = Path(__file__).parent.absolute()
repository_root = (here / ".." ).resolve()
sys.path.insert(0, str(repository_root))

import env

# Umbrella
inv_url = env.UMBRELLA.get("inv_url")
inv_token = env.UMBRELLA.get("inv_token")

# AMP
amp_host = env.AMP.get("host")
amp_client_id = env.AMP.get("client_id")
amp_api_key = env.AMP.get("api_key")

# TG
tg_host = env.THREATGRID.get("host")
tg_api_key = env.THREATGRID.get("api_key")

# Webex
room_id = env.WEBEX.get("room_id")
wx_token = env.WEBEX.get("personal_access_token")

def test_domain(domain_url, print_response="yes"):
    #Use a domain of your choice

    #Construct the API request to the Umbrella Investigate API to query for the status of the domain
    url = f"{inv_url}/domains/categorization/{domain_url}?showLabels"
    headers = {"Authorization": f'Bearer {inv_token}'}
    response = requests.get(url, headers=headers)

    #And don't forget to check for errors that may have occured!
    response.raise_for_status()

    #Make sure the right data in the correct format is chosen, you can use print statements to debug your code
    domain_status = response.json()[domain_url]["status"]

    if print_response == "yes":
        print("This is how the response data from Umbrella Investigate looks like: \n")
        pprint(response.json(), indent=4)

    if domain_status == 1:
        print(f"The domain {domain_url} is found CLEAN")
        return "clean"
    elif domain_status == -1:
        print(f"The domain {domain_url} is found MALICIOUS")
        return "malicious"
    elif domain_status == 0:
        print(f"The domain {domain_url} is found UNDEFINED")
        return "undefined"

    print("This is how the response data from Umbrella Investigate looks like: \n")
    pprint(response.json(), indent=4)

#Add another call here, where you check the historical data for either the domain from the intro or your own domain and print it out in a readable format
def historical(domain_url, print_response="yes"):
    # call API
    url = f"{inv_url}/pdns/domain/{domain_url}"
    headers = {"Authorization": f'Bearer {inv_token}'}
    response = requests.get(url, headers=headers)

    response.raise_for_status()
    
    # print historical data
    if print_response == "yes":
        print(f"This is the historical data Umbrella has for {domain_url}:")
        pprint(response.json(), indent=4)
    
    return response.json()

# Stage 1
def stage_1(domain_url):
    domain_status = test_domain(domain_url)
    domain_history = historical(domain_url)

    block_list = []
    if domain_status == "malicious":
        print(f"Domain {domain_url} is MALICIOUS!")
        sanitzed = domain_url.replace(".com", "(dot)com")
        block_list.append(sanitized)
        print(f"Added {sanitized} to blocklist.")
    elif domain_status == "clean":
        print(f"Hurray, domain {domain_url} is CLEAN!")
    else:
        print(f"Umbrella doesn't know whethere {domain_url} is MALICIOUS or not. Better not click it!")
        sanitzed = domain_url.replace(".com", "(dot)com")
        block_list.append(sanitized)
        print(f"Added {sanitized} to blocklist.")

    # hmm not working, couldnt manage to find any info on how to add to block list
    url = "https://management.api.umbrella.com/v1/organizations"   #10000474 org id
    headers = {"Accept": "application/json"}
    response = requests.request("GET", url, headers=headers)
    #print(response.text)

# Stage 2
def stage_2(client):

    # call API
    request = requests.get(f"https://{amp_client_id}:{amp_api_key}@{amp_host}/v1/event_types")
    response = resquest.json()

    for event in response:
        ip = event["computer"]["network_addresses"]["ip"]
        # find event types where malware was executed
        if event["event_type"] == "Executed malware":
            print(f"Host {ip} has executed malware!")
            #SHA256 = event["file"]["identity"]["sha256"] # not working due to API error
            SHA256 = "b1380fd95bc5c0729738dcda2696aa0a7c6ee97a93d992931ce717a0df523967"
            
            # isolate the endpoints where the malicious hash was seen
            isolation = isolate_hosts(SHA256)
            if isolation == "Success":
                print("Endpoint successfully isolated.")
            else:
                print("Could not isolate endpoint.")

            # investigate the hash with Threatgrid
            investigation = investigate(SHA256)


def isolate_hosts(SHA256):
    request = requests.get(f"https://{amp_client_id}:{amp_api_key}@{amp_host}/v1/computers/activity?SHA={SHA256}")
    response = reques.json()

    # fetch connector guids of all endpoints that have seen the SHA256
    connector_guids = []
    devices = reponse["data"]
    for i in devices:
        connector_guids.append(i["connector_guid"])
    
    # isolate endpoints
    for i in connector_guids:
        try:
            requests.put(f"https://{amp_client_id}:{amp_api_key}@{amp_host}/v1/computers/{i}/isolation")
            return "Success"
        except:
            print("Isolation could not be performed. Maybe a permission error?")
            return "Failed"

def investigate_sha(SHA256="b1380fd95bc5c0729738dcda2696aa0a7c6ee97a93d992931ce717a0df523967"):   

    # check if SHA was already submitted once
    request = requests.get(f"https://{tg_host}/api/v2/search/submissions?q={SHA256}&api_key={tg_api_key}")
    response = request.json()
    try:
        status = response["data"]["items"][0]["item"]["status"]
        print(f"Threatgrid found the SHA256 in its submissions. The status is: {status}")
        print("SHA256 will not be submitted again.")

        # information from the sha submission
        filename = response["data"]["items"][0]["item"]["filename"]
        submit_time = response["data"]["items"][0]["item"]["submitted_at"]

        with open("tg_sample_info.txt", "w") as file:
            # could not manage to fetch domains, instead fetching filename
            # writing to file
            file.write(filename + "\n")
        return filename, submit_time, response

    except:
        print(f"Threatgrid didn't find the SHA256 in its submissions.")
        print("SHA256 will be submitted.")
        # submit sample
        request = requests.get(f"https://{tg_host}/api/v2/samples?{SHA256}&api_key={tg_api_key}")
        
        # check if submission was valis
        if request.status_code == 200:
            print("Sample successfully submitted!")
        else:
            print("Oops something went wrong :(")
        

# Stage 3
def stage_3(url="www.heroku.com", SHA256="b1380fd95bc5c0729738dcda2696aa0a7c6ee97a93d992931ce717a0df523967"):
    # feed URL from TR in umbrella
    ################## API not working
    
    # investigate SHA from AMP with TG
    filename, submit_time, response = investigate_sha(SHA256)
    
    # Submit the info via Webex
    api = WebexTeamsAPI(wx_token)
    api.messages.create(roomId=room_id, 
                        markdown=f"🛰️ This **cool script** just found some information on a malicious hash:\n{SHA256}\n Malicious file: {filename} \nSample submission date: {submit_time}.")

    print("Done!")


################# testing area ######################
def amp_test():
    request = requests.get(f"https://{amp_client_id}:{amp_api_key}@{amp_host}/v1/audit_logs")
    response = reques.json()
    print(response)
    # retries exceeded

def tg_test(SHA256="b1380fd95bc5c0729738dcda2696aa0a7c6ee97a93d992931ce717a0df523967"):
    request = requests.post(f"https://{tg_host}/api/v2/samples?{SHA256}&api_key={tg_api_key}")
    response = request.json()
    print(response)
    # response "The parameter sample is required." ???