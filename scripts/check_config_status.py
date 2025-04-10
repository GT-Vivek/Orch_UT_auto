import requests
import time
import sys

def check_config_status(intent_id):
    """Checks the status of the uploaded Day 1 configuration and waits until 'isorchestrationover' is true."""
    status_url = 'http://10.4.5.167:8787/getDay1ConfigStatus'

    check_interval = 5 * 60  # 5 minutes
    max_check_time = 16 * 60  # 16 minutes
    elapsed_time = 0

    def is_orchestration_complete(status_data):
        """Return True if last item contains isorchestrationover: True."""
        if not isinstance(status_data, list) or not status_data:
            return False
        last_entry = status_data[-1]
        return isinstance(last_entry, dict) and last_entry.get("isorchestrationover") is True

    try:
        # Initial check
        response = requests.get(status_url, params={'intentName': intent_id})
        print(f"Debug info: url = {status_url} ; params = {{'intentName': {intent_id}}}")
        if response.status_code == 200:
            status_data = response.json()
            print("Initial configuration status response:", status_data)

            if is_orchestration_complete(status_data):
                print("Orchestration is complete for all devices.")
                return
            else:
                print("Orchestration is not yet complete for all devices. Checking every 5 minutes...")
        else:
            print(f"Failed to fetch configuration status. Status code: {response.status_code}, Response: {response.text}")
            return

        # Periodic checks
        while elapsed_time < max_check_time:
            time.sleep(check_interval)
            elapsed_time += check_interval

            response = requests.get(status_url, params={'intentName': intent_id})
            print(f"Debug info: url = {status_url} ; params = {{'intentName': {intent_id}}}")
            if response.status_code == 200:
                status_data = response.json()
                print("Configuration status response:", status_data)

                if is_orchestration_complete(status_data):
                    print("Orchestration is complete for all devices.")
                    return
                else:
                    print("Orchestration is not yet complete for all devices. Checking again in 5 minutes...")
            else:
                print(f"Failed to fetch configuration status. Status code: {response.status_code}, Response: {response.text}")

        print("Stopped checking after 16 minutes. Orchestration did not complete.")
    except Exception as e:
        print(f"An error occurred while checking configuration status: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python check_config_status.py <intent_id>")
        sys.exit(1)

    intent_id = sys.argv[1]
    check_config_status(intent_id)
