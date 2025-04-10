import requests
import json
import yaml

# Load configuration from YAML file
CONFIG_FILE = "/home/vivek/Orch_UT_auto/sample.yaml"

with open(CONFIG_FILE, "r") as file:
    config = yaml.safe_load(file)

# Extract devices from the YAML structure
DEVICES = [
    {
        "host": f"https://{device['ipAddress']}:8765",
        "username": device["Credentials"]["user"],
        "password": device["Credentials"]["password"]
    }
    for category in ["SSpine", "Spine", "Leaf", "Tor"]
    for device in config.get("Connectivity", {}).get(category, [])
]

# Extract interfaces to clear from the YAML structure
INTERFACES_TO_CLEAR = [
    link.split("|")[0].strip().split("_")[1]  # Extract the second part (e.g., "swp1" from "S1_swp1")
    for category in ["SSpine", "Spine", "Leaf", "Tor"]
    for device in config.get("Connectivity", {}).get(category, [])
    for link_entry in device.get("Links", [])[:1]  # Only take the first link for each device
    for link in [link_entry["link"]]
]

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

def get_revision_id(device):
    url = f"{device['host']}/nvue_v1/revision"
    print(f"Requesting new revision ID from {device['host']}...")
    print(f"URL: {url}")  # Print the URL being used
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
    print(f"Clearing configuration on {device['host']} using revision ID {revision_id}...")
    print(f"URL: {url}")  # Print the URL being used
    payload = {
        "router": None,
        "interface": {iface: None for iface in INTERFACES_TO_CLEAR},
        "qos": None,
        "vrf": {"default": {"router": {"bgp": None}}}
    }
    headers = {'Content-Type': 'application/json'}
    print(f"Payload: {json.dumps(payload)}")  # Print the payload being sent
    response = requests.patch(url, auth=(device['username'], device['password']), headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        print(f"Configuration cleared successfully on {device['host']}.")
    else:
        print(f"Failed to clear configuration on {device['host']}: {response.text}")

def apply_configuration(device, revision_id):
    url = f"{device['host']}/nvue_v1/revision/{revision_id}"
    print(f"Applying configuration on {device['host']} using revision ID {revision_id}...")
    print(f"URL: {url}")  # Print the URL being used
    payload = {"state": "apply", "auto-prompt": {"ays": "ays_yes"}}
    headers = {'Content-Type': 'application/json'}
    print(f"Payload: {json.dumps(payload)}")  # Print the payload being sent
    response = requests.patch(url, auth=(device['username'], device['password']), headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        print(f"Configuration applied successfully on {device['host']}.")
    else:
        print(f"Failed to apply configuration on {device['host']}: {response.text}")

def clean_devices():
    """Encapsulates the main logic for cleaning devices."""
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
    clean_devices()