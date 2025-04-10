import requests

def apply_config(template_path):
    """Uploads the Day 1 configuration to the specified API endpoint."""
    upload_url = 'http://10.4.5.167:8787/uploadDay1Config'

    try:
        with open(template_path, 'rb') as file:
            files = {'file': file}
            response = requests.post(upload_url, files=files)

        if response.status_code == 200:
            intent_id = response.text.strip()
            print(f"Intent uploaded successfully. Intent ID: {intent_id}")
            return intent_id
        else:
            print(f"Failed to upload intent. Status code: {response.status_code}, Response: {response.text}")
            return None
    except Exception as e:
        print(f"An error occurred while uploading the intent: {e}")
        return None
