import requests
import json
from pprint import pprint

from utils.auth import IntersightAuth, get_authenticated_aci_session
from env import config

def test_API(response):
    if response.status_code == 200:
        print("API call succeeded.")
    else:
        print(f"API call unsuccessfull {response.status_code}")   

# stage 0
# Autenticate to Intersight

auth=IntersightAuth(secret_key_filename=config["INTERSIGHT_CERT"],
                      api_key_id=config["INTERSIGHT_API_KEY"])

BASE_URL = "https://www.intersight.com/api/v1"

url = f"{BASE_URL}/cond/Alarms"
response = requests.get(url, auth=auth)
test_API(response)

result = response.json()
#pprint(result, indent=2)

# Retrieve NTP Policies

url = "https://intersight.com/api/v1/ntp/Policies"
response = requests.get(url, auth=auth)
test_API(response)
    
result = response.json()
pprint(result, indent=2)

# stage 1
# Alarms - Description
url = "https://www.intersight.com/api/v1/cond/Alarms"

response = requests.get(url, auth=auth)
test_API(response)
    
result = response.json()
#pprint(result, indent=2)

alarmDescriptions = []
for i in result["Results"]:
    alarmDescriptions.append(i["Description"])
    
print("Alarm descriptions:" , alarmDescriptions[0:5] , "...")

# Summary of Physical Infrastructure
url = "https://intersight.com/api/v1/compute/PhysicalSummaries"
response = requests.get(url, auth=auth)
test_API(response)
    
result = response.json()
#pprint(result, indent=2)

# add values to a separate list
mgmtModes, mgmtIPs, names, cpus, cpuCores, powerStates, firmwares, models, serials = [], [], [], [], [], [], [], [], []
for i in result["Results"]:
    mgmtModes.append(i["ManagementMode"])
    mgmtIPs.append(i["MgmtIpAddress"])
    names.append(i["Name"])
    cpus.append(i["NumCpus"])
    cpuCores.append(i["NumCpuCores"])
    powerStates.append(i["OperPowerState"])
    firmwares.append(i["Firmware"])
    models.append(i["Model"])
    serials.append(i["Serial"])
    
# License Tiers    
url = "https://intersight.com/api/v1/license/LicenseInfos"
response = requests.get(url, auth=auth)
test_API(response)    

result = response.json()
#pprint(result, indent=2)

licenseTiers = []
for i in result["Results"]:
    licenseTiers.append(i["LicenseType"])

# Compliance with Hardware Compatibility List (HCL). 
# OS Vendor and OS Version

url = "https://intersight.com/api/v1/cond/HclStatuses"
response = requests.get(url, auth=auth)
test_API(response)    

result = response.json()
#pprint(result, indent=2)

osVendors, osVersions = [], []
for i in result["Results"]:
    osVendors.append(i["HclOsVendor"])
    osVersions.append(i["HclOsVersion"])

print(osVendors)
print(osVersions)

# Extract Kubernetes Cluster Names
url = "https://intersight.com/api/v1/kubernetes/Clusters"
response = requests.get(url, auth=auth)
test_API(response)    

result = response.json()
#pprint(result, indent=2)

clusterName = []
for i in result["Results"]:
    clusterName.append(i["Name"])
    
print(clusterName)

# Count Kubernetes Cluster Deployments
url = "https://intersight.com/api/v1/kubernetes/Deployments"
params = {"$count": "True"}
response = requests.get(url, auth=auth, params=params)
test_API(response)    

result = response.json()
#pprint(result, indent=2)

k8sCount = result["Count"]
print("Number of deployments:" , k8sCount)

