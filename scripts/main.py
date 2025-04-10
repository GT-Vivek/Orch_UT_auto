from clean_devices import clean_devices
from apply_config import apply_config
from check_config_status import check_config_status
from compare_device_config import compare_device_config
import time

def main():
    try:
        print("Starting device cleanup...")
        clean_devices()
        print("Device cleanup completed.\n")

        time.sleep(20)

        yaml_file = "/home/vivek/Orch_UT_auto/sample.yaml"

        print("Applying configuration...")
        intent_id = apply_config(yaml_file)  # Capture the intent ID returned by apply_config
        if not intent_id or intent_id.strip() == "":
            print("Failed to apply configuration. Exiting...")
            return
        print(f"Configuration applied successfully. Intent ID: {intent_id}\n")

        time.sleep(5)

        print("Checking configuration status...")
        check_config_status(intent_id)
        print("Configuration status check completed.\n")

        print("Comparing device configuration...")
        compare_device_config(yaml_file)
        print("Device configuration comparison completed.\n")

        print("All tasks completed successfully.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()