import requests

# Define the correct API endpoint for Day 1 configuration upload
upload_url = 'http://10.4.5.167:8787/uploadDay1Config'

# Path to your intent YAML file
template_path = '/home/vivek/ones-pyapi/examples/day1fm/yaml-templates/test.yaml'

# Prepare the file for upload
with open(template_path, 'rb') as file:
    files = {'file': file}
    response = requests.post(upload_url, files=files)

# Check the response
if response.status_code == 200:
    intent_id = response.text
    print(f"Intent uploaded successfully. Intent ID: {intent_id}")
else:
    print(f"Failed to upload intent. Status code: {response.status_code}, Response: {response.text}")