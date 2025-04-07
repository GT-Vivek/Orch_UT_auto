import requests
import json

# Define constants
DEVICES = [
    {"host": "https://10.4.5.245:8765", "username": "cumulus", "password": "YourPaSsWoRd1$"},
    {"host": "https://10.4.5.129:8765", "username": "cumulus", "password": "YourPaSsWoRd1$"},
    {"host": "https://10.4.5.210:8765", "username": "cumulus", "password": "YourPaSsWoRd1$"}
]
INTERFACES_TO_CLEAR = ["swp3"]

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

def get_revision_id(device):
    url = f"{device['host']}/nvue_v1/revision"
    print(f"Requesting new revision ID from {device['host']}...")
    response = requests.post(url, auth=(device['username'], device['password']), verify=False)
    if response.status_code == 200:
        revision_data = response.json()
        if revision_data:
            revision_id = list(revision_data.keys())[0]  # Extracting the first key as revision ID
            print(f"Received revision ID {revision_id} from {device['host']}.")
            return revision_id
    print(f"Failed to get revision ID from {device['host']}: {response.text}")
    return None

def clear_configuration(device, revision_id):
    url = f"{device['host']}/nvue_v1/?rev={revision_id}"
    payload = {
        "router": None,
        "interface": {iface: None for iface in INTERFACES_TO_CLEAR},
        "qos": None,
        "vrf": {"default": {"router": {"bgp": None}}}
    }
    headers = {'Content-Type': 'application/json'}
    print(f"Clearing configuration on {device['host']} using revision ID {revision_id}...")
    response = requests.patch(url, auth=(device['username'], device['password']), headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        print(f"Configuration cleared successfully on {device['host']}.")
    else:
        print(f"Failed to clear configuration on {device['host']}: {response.text}")

def apply_configuration(device, revision_id):
    url = f"{device['host']}/nvue_v1/revision/{revision_id}"
    payload = {"state": "apply", "auto-prompt": {"ays": "ays_yes"}}
    headers = {'Content-Type': 'application/json'}
    print(f"Applying configuration on {device['host']} using revision ID {revision_id}...")
    response = requests.patch(url, auth=(device['username'], device['password']), headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        print(f"Configuration applied successfully on {device['host']}.")
    else:
        print(f"Failed to apply configuration on {device['host']}: {response.text}")

def main():
    for device in DEVICES:
        try:
            print(f"\nProcessing device {device['host']}...")
            revision_id = get_revision_id(device)
            if revision_id:
                clear_configuration(device, revision_id)
                apply_configuration(device, revision_id)
            else:
                print(f"Skipping configuration for {device['host']} due to missing revision ID.")
        except requests.exceptions.RequestException as e:
            print(f"Network error occurred for {device['host']}: {e}")
        except Exception as e:
            print(f"Unexpected error occurred for {device['host']}: {e}")

if __name__ == "__main__":
    main()