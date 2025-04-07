# Orch_UT_auto

## Overview
This repository provides Python scripts tailored for automating configuration management, validation, and status checks specifically for Cumulus devices and their associated APIs. Below is a detailed summary of the key scripts and their functionalities:

### 1. **Apply_config.py**
This script uploads a Day 1 configuration file (`test.yaml`) to a designated API endpoint.

- **API Endpoint**: `http://10.4.5.167:8787/uploadDay1Config`
- **YAML File Path**: `/home/vivek/ones-pyapi/examples/day1fm/yaml-templates/test.yaml`
- **Functionality**:
    - Sends an HTTP POST request using the `requests` library.
    - Attaches the YAML file to the request for upload.

---

### 2. **check_config_status.py**
This script queries the ONES FM server to verify the status of a previously uploaded Day 1 configuration.

- **API Endpoint**: `http://10.4.5.167:8787/getDay1ConfigStatus`
- **Parameter**: Intent ID (`test.yaml_20250328131205`)
- **Functionality**:
    - Sends an HTTP GET request to retrieve the configuration status.

---

### 3. **clean_devices.py**
This script automates the cleanup of configurations on multiple Cumulus Linux devices using the NVUE API.

- **Functionality**:
    - Fetches a new revision ID from the NVUE API.
    - Clears configurations such as:
        - Interface settings
        - BGP under the default VRF
        - QoS
        - Router configurations
    - Applies and commits the configuration changes.

---

### 4. **compare_device_config.py**
This script validates the configurations of Cumulus devices by comparing them against expected values.

- **Functionality**:
        - **BGP Configuration Checks**:
                - Validates ASN, neighbors, path selection, graceful restart, redistribution, and peer groups.
        - **Interface and IP Checks**:
                - Verifies loopback IPs, interface IPs, and interface statuses.
        - **QoS and BFD Validation**:
                - Ensures proper QoS (e.g., PFC, RoCE) and BFD configurations.
        - **Adaptive Routing**:
                - Checks if Adaptive Routing is enabled on specific interfaces.
        - **Host-Specific Checks**:
                - Validates host interface IPs, routes, MTU, and hostname.
        - **Ping Connectivity**:
                - Tests network connectivity between devices using loopback IPs.

---

## Summary
The scripts in this repository are designed to simplify and automate network configuration management, validation, and monitoring for Cumulus devices. By leveraging APIs and automation, they ensure consistency, accuracy, and efficiency in network operations.