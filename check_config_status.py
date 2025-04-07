import requests

# Define the ONES FM server URL for checking status
status_url = 'http://10.4.5.167:8787/getDay1ConfigStatus'

# Use the intent ID from your upload response
intent_id = "test.yaml_20250328131205"

# Send a GET request with the intent ID as a parameter
response = requests.get(status_url, params={'intentName': intent_id})

# Print the response
print(f"Debug info: url = {status_url} ; params = {{'intentName': {intent_id}}}")
print("Response:", response.text)