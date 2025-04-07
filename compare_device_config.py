import paramiko
import yaml
import sys
import re
import ipaddress
import json

def log_message(level, message):
    print(f"[{level.upper()}] {message}")

def load_yaml(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

def ssh_connect(host, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=host, username=username, password=password)
        return client
    except Exception as e:
        log_message("error", f"Failed to connect to {host}: {e}")
        return None

def execute_sudo_command(client, command, sudo_password):
    try:
        stdin, stdout, stderr = client.exec_command(f"echo {sudo_password} | sudo -S {command}")
        output = stdout.read().decode()
        return output.strip()
    except Exception as e:
        log_message("error", f"Error executing sudo command: {e}")
        return None

def check_bgp_config(client, expected_asn, password):
    command = "vtysh -c 'show ip bgp summary'"
    output = execute_sudo_command(client, command, password)
    print(f"Output of command '{command}':\n {output}")

    if not output:
        log_message("error", "Failed to fetch BGP configuration.")
        return "Error fetching BGP config"

    match = re.search(r"local AS number (\d+)", output)
    if not match:
        log_message("error", "Could not find local AS number in BGP configuration output.")
        return f"Could not find ASN: Expected {expected_asn}, found None"

    found_asn = match.group(1)
    if found_asn != str(expected_asn):
        log_message("error", f"ASN mismatch detected. Expected ASN: {expected_asn}, Found ASN: {found_asn}")
        return f"ASN mismatch: Expected {expected_asn}, found {found_asn}"

    log_message("info", f"BGP ASN match: {found_asn}")
    return f"MATCH (ASN {found_asn})"

def check_bgp_neighbors(client, password):
    command = "vtysh -c 'show ip bgp summary'"
    output = execute_sudo_command(client, command, password)

    if not output:
        log_message("error", "Failed to fetch BGP neighbors.")
        return "Error fetching BGP neighbors"

    # Regex to capture neighbor details (hostname or IP)
    neighbor_pattern = r"(\S+)\((\d+\.\d+\.\d+\.\d+)\)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+\S+\s+(\S+)"
    matches = re.findall(neighbor_pattern, output)

    if not matches:
        log_message("info", "No BGP neighbors found.")
        return "No BGP neighbors found"

    neighbors = {ip: asn for _, ip, asn in matches}
    log_message("info", f"Found BGP neighbors:\n  - {', '.join(neighbors.keys())}")

    return neighbors

def check_bgp_path_selection_and_graceful_restart(client, password):
    command = "nv show vrf default router bgp path-selection"
    output = execute_sudo_command(client, command, password)
    print(f"Output of command '{command}':\n {output}")

    if not output:
        log_message("error", "Failed to fetch BGP path selection configuration.")
        return "Error fetching BGP path selection configuration"

    # Expected BGP path selection configuration
    expected_path_selection_config = {
        "routerid-compare": "off",
        "aspath compare-lengths": "on",
        "aspath compare-confed": "off",
        "med compare-always": "off",
        "med compare-deterministic": "on",
        "med compare-confed": "off",
        "med missing-as-max": "off",
        "multipath aspath-ignore": "on",
        "multipath generate-asset": "off",
        "multipath bandwidth": "all-paths"
    }

    # Regex patterns for BGP path selection
    path_selection_patterns = {
        "routerid-compare": r"^\s*routerid-compare\s+(\S+)",
        "aspath compare-lengths": r"^\s*compare-lengths\s+(\S+)",
        "aspath compare-confed": r"^\s*compare-confed\s+(\S+)",
        "med compare-always": r"^\s*compare-always\s+(\S+)",
        "med compare-deterministic": r"^\s*compare-deterministic\s+(\S+)",
        "med compare-confed": r"^\s*compare-confed\s+(\S+)",
        "med missing-as-max": r"^\s*missing-as-max\s+(\S+)",
        "multipath aspath-ignore": r"^\s*aspath-ignore\s+(\S+)",
        "multipath generate-asset": r"^\s*generate-asset\s+(\S+)",
        "multipath bandwidth": r"^\s*bandwidth\s+(\S+)"
    }

    mismatches = []
    matched_values = {}
    for key, pattern in path_selection_patterns.items():
        match = re.search(pattern, output, re.MULTILINE)
        if match:
            value = match.group(1)
            if value != expected_path_selection_config[key]:
                mismatches.append(f"{key}: Expected {expected_path_selection_config[key]}, Found {value}")
            else:
                matched_values[key] = value
        else:
            mismatches.append(f"{key}: Not found in output")

    if mismatches:
        log_message("error", f"BGP path selection mismatch detected: {', '.join(mismatches)}")
        return f"MISMATCH: {', '.join(mismatches)}"

    # Log matched values in a structured format
    log_message("info", "BGP Path Selection Configuration:")
    for key, value in matched_values.items():
        log_message("info", f"  - {key.replace('-', ' ').capitalize()}: {value}")

    log_message("info", "BGP path selection configuration matches expected values.")

    # Check BGP graceful restart
    command = "nv show router bgp graceful-restart"
    output = execute_sudo_command(client, command, password)

    if not output:
        log_message("error", "Failed to fetch BGP graceful restart configuration.")
        return "Error fetching BGP graceful restart configuration"

    # Expected BGP graceful restart configuration
    expected_graceful_restart_config = {
        "mode": "helper-only",
        "restart-time": "1",
        "path-selection-deferral-time": "0",
        "stale-routes-time": "1"
    }

    # Regex patterns for BGP graceful restart
    graceful_restart_patterns = {
        "mode": r"^\s*mode\s+(\S+)",
        "restart-time": r"^\s*restart-time\s+(\d+)",
        "path-selection-deferral-time": r"^\s*path-selection-deferral-time\s+(\d+)",
        "stale-routes-time": r"^\s*stale-routes-time\s+(\d+)"
    }

    mismatches = []
    matched_values = {}
    for key, pattern in graceful_restart_patterns.items():
        match = re.search(pattern, output, re.MULTILINE)
        if match:
            value = match.group(1)
            if value != expected_graceful_restart_config[key]:
                mismatches.append(f"{key}: Expected {expected_graceful_restart_config[key]}, Found {value}")
            else:
                matched_values[key] = value
        else:
            mismatches.append(f"{key}: Not found in output")

    if mismatches:
        log_message("error", f"BGP graceful restart mismatch detected: {', '.join(mismatches)}")
        return f"MISMATCH: {', '.join(mismatches)}"

    # Log matched values in a structured format
    log_message("info", "BGP Graceful Restart Configuration:")
    for key, value in matched_values.items():
        log_message("info", f"  - {key.replace('-', ' ').capitalize()}: {value}")

    log_message("info", "BGP graceful restart configuration matches expected values.")
    return "MATCH (BGP path selection and graceful restart configurations are correct)"

def check_bfd_config(client, password):
    command = "nv show vrf default router bgp peer-group overlay bfd"
    output = execute_sudo_command(client, command, password)
    print(f"Output of command '{command}':\n {output}")

    if not output:
        log_message("error", "Failed to fetch BFD configuration.")
        return "Error fetching BFD configuration"

    # Expected BFD configuration
    expected_bfd_config = {
        "enable": "on",
        "detect-multiplier": "3",
        "min-rx-interval": "300",
        "min-tx-interval": "300"
    }

    # Regex patterns for BFD configuration
    bfd_patterns = {
        "enable": r"^\s*enable\s+(\S+)",
        "detect-multiplier": r"^\s*detect-multiplier\s+(\d+)",
        "min-rx-interval": r"^\s*min-rx-interval\s+(\d+)",
        "min-tx-interval": r"^\s*min-tx-interval\s+(\d+)"
    }

    mismatches = []
    matched_values = {}
    for key, pattern in bfd_patterns.items():
        match = re.search(pattern, output, re.MULTILINE)
        if match:
            value = match.group(1)
            if value != expected_bfd_config[key]:
                mismatches.append(f"{key}: Expected {expected_bfd_config[key]}, Found {value}")
            else:
                matched_values[key] = value
        else:
            mismatches.append(f"{key}: Not found in output")

    if mismatches:
        log_message("error", f"BFD configuration mismatch detected: {', '.join(mismatches)}")
        return f"MISMATCH: {', '.join(mismatches)}"

    # Log matched values
    log_message("info", "BFD Configuration:")
    for key, value in matched_values.items():

        log_message("info", f"  - {key.replace('-', ' ').capitalize()}: {value}")

    return f"MATCH (BFD configuration is correct)\nMatched Values: {matched_values}"

def check_loopback_ip(client, expected_pool, password):
    command = "ip -o addr show lo"
    output = execute_sudo_command(client, command, password)

    if not output:
        log_message("error", "Failed to fetch loopback IP configuration.")
        return "Error fetching loopback IP"

    ip_pattern = r"inet (\d+\.\d+\.\d+\.\d+)/\d+"
    matches = re.findall(ip_pattern, output)

    if not matches:
        log_message("info", "No loopback IP found.")
        return "No loopback IP found"

    expected_network = ipaddress.ip_network(expected_pool, strict=False)
    for ip in matches:
        if ipaddress.ip_address(ip) in expected_network:
            log_message("info", f"Loopback IP {ip} is within the expected pool {expected_pool}.")
            return f"MATCH ({ip})"

    log_message("warning", f"Loopback IPs {matches} are not in the expected pool {expected_pool}.")
    return f"MISMATCH: {matches} not in {expected_pool}"

def check_interface_ips(client, expected_pool, interfaces_to_check, password):
    command = "ip -j addr show"
    output = execute_sudo_command(client, command, password)

    if output is None or not output:
        log_message("error", "Failed to fetch interface IPs.")
        return "Error fetching interface IPs"

    try:
        interfaces = json.loads(output)
    except json.JSONDecodeError:
        log_message("error", "Failed to parse IP address data.")
        return "Failed to parse IP address data"

    expected_network = ipaddress.ip_network(expected_pool, strict=False)
    mismatched_interfaces = []

    for iface in interfaces:
        if iface["ifname"] in interfaces_to_check:
            assigned_ips = [addr["local"] for addr in iface.get("addr_info", [])]
            valid_ips = [ip for ip in assigned_ips if ipaddress.ip_address(ip) in expected_network]

            if valid_ips:
                log_message("info", f"MATCH: {iface['ifname']} has IPs in subnet {expected_pool}: {', '.join(valid_ips)}")
                return f"MATCH ({iface['ifname']}: {', '.join(valid_ips)})"
            else:
                ip_info = f"{iface['ifname']}: {', '.join(assigned_ips)}" if assigned_ips else f"{iface['ifname']}: No IP assigned"
                mismatched_interfaces.append(ip_info)
                log_message("warning", f"MISMATCH: {iface['ifname']} has no IPs in subnet {expected_pool}. Found: {ip_info}")

    if mismatched_interfaces:
        log_message("error", f"MISMATCH: No IPs in {expected_pool} for interfaces. Details: {', '.join(mismatched_interfaces)}")
        return f"MISMATCH: No IPs in {expected_pool} | Actual: {', '.join(mismatched_interfaces)}"
    else:
        log_message("error", f"MISMATCH: No interfaces found in subnet {expected_pool}.")
        return f"MISMATCH: No interfaces found in {expected_pool}"

def check_interface_status(client, interfaces_to_check, password):
    command = "nv show interface"
    output = execute_sudo_command(client, command, password)

    if output is None or not output:
        log_message("error", "Failed to fetch interface status.")
        return "Error fetching interface status"

    print("Parsing interface status output...")
    status_info = []
    lines = output.splitlines()
    if len(lines) < 3:
        log_message("warning", "Interface status output is missing expected header or data.")
        return "No interface status data available"

    for line in lines[2:]:
        parts = line.split()
        if len(parts) >= 3:
            ifname = parts[0]
            adminstate = parts[1]
            operstate = parts[2]
            if ifname in interfaces_to_check:
                status_info.append(f"{ifname}: Admin={adminstate}, Oper={operstate}")

    if not status_info:
        log_message("warning", "No matching interfaces found in the status output.")
        return "No matching interfaces found in the status output"

    log_message("info", "Interface status check completed successfully.")
    return "\n".join(status_info)

def extract_interfaces_from_links(links):
    interfaces = set()
    for link in links:
        if 'link' in link:
            parts = link['link'].split(' | ')
            for part in parts:
                if '_' in part:
                    iface = part.split('_')[1]
                    interfaces.add(iface)
                else:
                    log_message("warning", f"Invalid link format: {part}")
    return list(interfaces)

def check_adaptive_routing(client, interfaces_to_check, password):
    """
    Check Adaptive Routing configuration on the provided interfaces.
    """
    mismatches = []
    matched_interfaces = []

    for interface in interfaces_to_check:
        command = f"nv show interface {interface} router adaptive-routing"
        output = execute_sudo_command(client, command, password)
        print(f"Output of command '{command}':\n {output}")

        if not output:
            log_message("error", f"Failed to fetch Adaptive Routing configuration for {interface}.")
            mismatches.append(f"{interface}: Error fetching configuration")
            continue

        # Parse the output to check if Adaptive Routing is enabled
        match = re.search(r"enable\s+(\S+)", output)
        if match:
            status = match.group(1)
            if status == "on":
                matched_interfaces.append(interface)
                log_message("info", f"MATCH: Adaptive Routing is enabled on {interface}.")
            else:
                mismatches.append(f"{interface}: Adaptive Routing is not enabled (Found: {status})")
        else:
            mismatches.append(f"{interface}: Could not parse Adaptive Routing status.")

    if mismatches:
        log_message("error", f"Adaptive Routing mismatches detected: {', '.join(mismatches)}")
        return f"MISMATCH: {', '.join(mismatches)}"

    log_message("info", f"Adaptive Routing is correctly configured on interfaces: {', '.join(matched_interfaces)}")
    return f"MATCH (Adaptive Routing enabled on: {', '.join(matched_interfaces)})"

def check_qos_config(client, password):
    def execute_and_check(command, expected_values, regex_patterns):
        output = execute_sudo_command(client, command, password)
        print(f"Output of command '{command}':\n {output}")
        if output is None:
            log_message("error", f"Failed to fetch output for command: {command}")
            return None, [f"Error fetching output for {command}"]

        matches = {}
        mismatches = []
        extracted_values = {}

        for key, pattern in regex_patterns.items():
            match = re.search(pattern, output)
            if match:
                extracted_value = match.group(1).strip()
                extracted_values[key] = extracted_value

        for key, expected_value in expected_values.items():
            extracted_value = extracted_values.get(key)

            if extracted_value is None:
                mismatches.append(f"{key}: Not found in output")
            elif extracted_value == expected_value:
                matches[key] = extracted_value
            else:
                mismatches.append(f"Mismatch in {key}: Expected {expected_value}, Got {extracted_value}")

        return matches, mismatches

    print("Starting QoS configuration check...")
    expected_qos = {
        "pfc-watchdog": {"polling-interval": "0:00:00.100000", "robustness": "3"},
        "roce": {"enable": "on", "mode": "lossless"},
        "pfc": {"port-buffer": "344.73 KB", "xoff-threshold": "63.48 KB",
                "xon-threshold": "63.48 KB", "switch-priority": "3"},
    }

    regex_patterns = {
        "polling-interval": r"polling-interval\s+\S+\s+(\S+)",
        "robustness": r"robustness\s+\S+\s+(\d+)",
        "enable": r"enable\s+(\S+)",
        "mode": r"mode\s+\S+\s+(\S+)",
        "port-buffer": r"default-global\s+\S+\s+([\d.]+\s+KB)\s+\S+\s+\S+\s+[\d.]+\s+KB\s+[\d.]+\s+KB",
        "xoff-threshold": r"default-global\s+\S+\s+[\d.]+\s+KB\s+\S+\s+\S+\s+([\d.]+\s+KB)\s+[\d.]+\s+KB",
        "xon-threshold": r"default-global\s+\S+\s+[\d.]+\s+KB\s+\S+\s+\S+\s+[\d.]+\s+KB\s+([\d.]+\s+KB)",
        "switch-priority": r"switch-priority:\s+(\d+)"
    }

    qos_matches, qos_mismatches = execute_and_check("nv show qos", expected_qos["roce"], regex_patterns)
    pfc_matches, pfc_mismatches = execute_and_check("nv show qos pfc", expected_qos["pfc"], regex_patterns)
    watchdog_matches, watchdog_mismatches = execute_and_check("nv show qos pfc-watchdog", expected_qos["pfc-watchdog"], regex_patterns)

    matched_values = {**qos_matches, **pfc_matches, **watchdog_matches}
    mismatched_values = qos_mismatches + pfc_mismatches + watchdog_mismatches

    print("Generating QoS configuration report...")
    result_report = "\nMatched Values:\n" + "\n".join([f"{k}: {v}" for k, v in matched_values.items()])

    if mismatched_values:
        result_report += "\nMismatched Values:\n" + "\n".join(mismatched_values)
        result_report += "\nQoS: QoS MISMATCH"
        log_message("error", "QoS configuration mismatch detected.")
    else:
        result_report += "\nQoS: QoS CONFIG MATCH"
        log_message("info", "QoS configuration matches expected values.")

    log_message("info", "QoS configuration check completed.")
    return result_report

def check_bgp_redistribute(client, device_type, password):
    """
    Check BGP redistribution configuration for spine or leaf devices.
    """
    command = "nv show vrf default router bgp address-family ipv4-unicast redistribute"
    output = execute_sudo_command(client, command, password)
    print(f"Output of command '{command}':\n {output}")

    if not output:
        log_message("error", "Failed to fetch BGP redistribution configuration.")
        return "Error fetching BGP redistribution configuration"

    # Expected configurations for spine and leaf devices
    expected_config = {
        "spine": {
            "static": {"enable": "on", "metric": "auto", "route-map": "none"},
            "connected": {"enable": "on", "metric": "auto", "route-map": "lo-to-bgp"},
            "kernel": {"enable": "off"},
            "ospf": {"enable": "off"}
        },
        "leaf": {
            "static": {"enable": "on", "metric": "auto", "route-map": "none"},
            "connected": {"enable": "on", "metric": "auto", "route-map": "hgx_subnets"},
            "kernel": {"enable": "off"},
            "ospf": {"enable": "off"}
        }
    }

    # Select the expected configuration based on the device type
    if device_type not in expected_config:
        log_message("error", f"Invalid device type: {device_type}")
        return f"Invalid device type: {device_type}"

    expected = expected_config[device_type]

    # Regex patterns to extract the configuration
    patterns = {
        "static": r"static\s+enable\s+(\S+)\s+metric\s+(\S+)\s+route-map\s+(\S+)",
        "connected": r"connected\s+enable\s+(\S+)\s+metric\s+(\S+)\s+route-map\s+(\S+)",
        "kernel": r"kernel\s+enable\s+(\S+)",
        "ospf": r"ospf\s+enable\s+(\S+)"
    }

    mismatches = []
    matched_values = {}

    for key, pattern in patterns.items():
        match = re.search(pattern, output, re.MULTILINE)
        if match:
            if key in ["static", "connected"]:
                enable, metric, route_map = match.groups()
                if enable != expected[key]["enable"] or metric != expected[key]["metric"] or route_map != expected[key]["route-map"]:
                    mismatches.append(f"{key}: Expected {expected[key]}, Found enable={enable}, metric={metric}, route-map={route_map}")
                else:
                    matched_values[key] = {"enable": enable, "metric": metric, "route-map": route_map}
            else:
                enable = match.group(1)
                if enable != expected[key]["enable"]:
                    mismatches.append(f"{key}: Expected enable={expected[key]['enable']}, Found enable={enable}")
                else:
                    matched_values[key] = {"enable": enable}
        else:
            mismatches.append(f"{key}: Not found in output")

    log_message("info", "BGP Redistribution Configuration:")
    for key, value in matched_values.items():
        log_message("info", f"  - {key.capitalize()}: {value}")

    if mismatches:
        log_message("error", f"BGP redistribution mismatch detected: {', '.join(mismatches)}")
        return f"MISMATCH: {', '.join(mismatches)}"

    log_message("info", "BGP redistribution configuration matches expected values.")
    return "MATCH (BGP redistribution configuration is correct)"

def check_bgp_peer_groups(client, password):
    command = "nv show vrf default router bgp peer-group"
    output = execute_sudo_command(client, command, password)
    print(f"Output of command '{command}':\n {output}")

    if not output:
        log_message("error", "Failed to fetch BGP peer groups.")
        return "Error fetching BGP peer groups"

    # Check for the presence of 'underlay_spine' and 'underlay_leaf'
    required_peer_groups = {"underlay_spine", "underlay_leaf"}
    found_peer_groups = set()

    for line in output.splitlines():
        # Extract the peer group name
        parts = line.split()
        if parts:
            peer_group_name = parts[0]
            if peer_group_name in required_peer_groups:
                found_peer_groups.add(peer_group_name)

    missing_peer_groups = required_peer_groups - found_peer_groups
    if missing_peer_groups:
        log_message("error", f"Missing BGP peer groups: {', '.join(missing_peer_groups)}")
        return f"MISMATCH: Missing peer groups: {', '.join(missing_peer_groups)}"

    log_message("info", f"All required BGP peer groups are present: {', '.join(found_peer_groups)}")
    return f"MATCH (Peer groups: {', '.join(found_peer_groups)})"

def verify_ping(client: paramiko.SSHClient, target_ip: str, password: str) -> str:
    command = f"ping -c 4 {target_ip} --no-vrf-switch"
    output = execute_sudo_command(client, command, password)

    if not output:
        log_message("error", f"Failed to execute ping command to {target_ip}.")
        return f"Error executing ping to {target_ip}"

    # Filter out irrelevant lines (e.g., vrf-wrapper.sh messages)
    filtered_output = "\n".join(
        line for line in output.splitlines() if not line.startswith("vrf-wrapper.sh")
    )

    if not filtered_output.strip():
        log_message("error", f"Filtered ping output is empty for {target_ip}.")
        return f"Error: Filtered ping output is empty for {target_ip}"

    # Adjusted regex patterns
    packet_loss_pattern = r"(\d+)% packet loss"
    rtt_pattern = r"rtt min/avg/max/mdev = (\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+) ms"

    packet_loss_match = re.search(packet_loss_pattern, filtered_output)
    rtt_match = re.search(rtt_pattern, filtered_output)

    if packet_loss_match:
        packet_loss = packet_loss_match.group(1)

        if packet_loss == "0":
            if rtt_match:
                rtt_min, rtt_avg, rtt_max, rtt_mdev = rtt_match.groups()
                log_message(
                    "info",
                    f"Ping to {target_ip}: SUCCESS (RTT: min={rtt_min}ms, avg={rtt_avg}ms, max={rtt_max}ms, mdev={rtt_mdev}ms)"
                )
                return "(Ping successful)"
            else:
                log_message("info", f"Ping to {target_ip}: SUCCESS (No RTT details available)")
                return "(Ping successful)"
        else:
            log_message("error", f"Ping to {target_ip}: FAILED ({packet_loss}% packet loss)")
            return f"Ping failed with {packet_loss}% packet loss"

    log_message("error", f"Failed to parse ping output for {target_ip}.")
    return f"Error parsing ping output for {target_ip}"

def verify_network_connectivity(yaml_file):
    with open(yaml_file, 'r') as f:
        inventory = yaml.safe_load(f)

    devices = []
    for spine in inventory['Connectivity']['Spine']:
        devices.append({
            'name': spine['switchName'],
            'user': spine['Credentials']['user'],
            'password': spine['Credentials']['password'],
            'type': 'Spine'
        })
    for leaf in inventory['Connectivity']['Leaf']:
        devices.append({
            'name': leaf['switchName'],
            'user': leaf['Credentials']['user'],
            'password': leaf['Credentials']['password'],
            'type': 'Leaf'
        })
    for host in inventory['Connectivity'].get('Host', []):
        devices.append({
            'name': host['hostName'],
            'user': host['Credentials']['user'],
            'password': host['Credentials']['password'],
            'type': 'Host'
        })

    # Get the loopback IP pool from the YAML file
    loopback_pool = inventory.get('IPv4Pool', {}).get('Loopback')

    results = {}

    for source in devices:
        results[source['name']] = []
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            log_message("info", f"Connecting to {source['name']}")
            client.connect(hostname=source['name'], username=source['user'], password=source['password'], timeout=10)

            # Fetch loopback IP dynamically and validate against the YAML pool
            loopback_check_result = check_loopback_ip(client, loopback_pool, source['password'])
            if "MATCH" in loopback_check_result:
                source_loopback_ip = loopback_check_result.split('(')[1].split(')')[0]
            else:
                log_message("error", f"Failed to fetch valid loopback IP for {source['name']}")
                continue

            for target in devices:
                if source_loopback_ip == target.get('loopback_ip', ''):
                    continue
                result = verify_ping(client, target.get('loopback_ip', ''), source['password'])
                results[source['name']].append((target['name'], result))

        except Exception as e:
            log_message("error", f"Failed to connect to {source['name']}: {str(e)}")
            results[source['name']].append(("ALL", f"Connection failed: {str(e)}"))
        finally:
            client.close()

    # Log results
    for source, pings in results.items():
        log_message("info", f"Ping results from {source}:")
        for target, result in pings:
            log_message("result", f"  To {target}: {result}")

    return results

def check_host_interface_ips(client, interfaces_to_check, host_pool, password):
    command = "ip -j addr show"
    output = execute_sudo_command(client, command, password)

    if output is None or not output:
        return "Error fetching interface IPs on host"

    try:
        interfaces = json.loads(output)
    except json.JSONDecodeError:
        return "Failed to parse IP address data on host"

    expected_network = ipaddress.ip_network(host_pool, strict=False)
    mismatched_interfaces = []

    for iface in interfaces:
        if iface["ifname"] in interfaces_to_check:
            assigned_ips = [
                addr["local"] for addr in iface.get("addr_info", [])
                if addr.get("family") == "inet"
            ]
            valid_ips = [ip for ip in assigned_ips if ipaddress.ip_address(ip) in expected_network]

            if valid_ips:
                log_message("info", f"MATCH: {iface['ifname']} has IPs in subnet {host_pool}: {', '.join(valid_ips)}")
            else:
                mismatched_interfaces.append(
                    f"{iface['ifname']}: No IPs in subnet {host_pool}, Found {', '.join(assigned_ips) if assigned_ips else 'None'}"
                )

    if mismatched_interfaces:
        return f"MISMATCH: {', '.join(mismatched_interfaces)}"
    return "All interface IPs are within the specified subnet on host"

def check_host_routes(client, expected_routes, password):
    command = "ip route show"
    output = execute_sudo_command(client, command, password)

    if output is None or not output:
        return "Error fetching routes on host"

    missing_routes = []
    for route in expected_routes:
        if route not in output:
            
            missing_routes.append(route)

    if missing_routes:
        return f"MISMATCH: Missing routes: {', '.join(missing_routes)}"

    # Print the routes found
    log_message("info", f"Routes found on host:\n{output}")
    return ""

def execute_command(client, command):
    try:
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode().strip()
        error_output = stderr.read().decode().strip()

        if error_output:
            log_message("error", f"Error executing command '{command}': {error_output}")
            return None

        return output

    except paramiko.SSHException as ssh_error:
        log_message("error", f"SSH error: {ssh_error}")
    except Exception as e:
        log_message("error", f"Error executing command '{command}': {e}")

    return None

def check_host_mtu(client, interfaces_to_check):
    command = "ip a"
    output = execute_command(client, command)
    if not output:
        log_message("error", "Failed to fetch MTU information. Check command execution permissions.")
        return "Error fetching MTU information"

    mtu_results = []
    current_interface = None

    for line in output.splitlines():
        # Match interface lines (e.g., "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 ...")
        interface_match = re.match(r"^\d+: (\S+):.*mtu (\d+)", line)
        if interface_match:
            current_interface = interface_match.group(1)
            mtu = interface_match.group(2)
            if current_interface in interfaces_to_check:
                mtu_results.append(f"{current_interface}: MTU={mtu}")

    if not mtu_results:
        return "No matching interfaces found or MTU information unavailable."

    return "\n".join(mtu_results)

def check_host_hostname(client, expected_hostname):
    command = "hostname"
    output = execute_command(client, command)
    if not output:
        log_message("error", "Failed to fetch hostname. Check command execution permissions.")
        return "Error fetching hostname"

    if output.strip() == expected_hostname:
        return f"MATCH (Hostname: {output.strip()})"
    else:
        return f"MISMATCH: Expected {expected_hostname}, Found {output.strip()}"

def verify_device(device, config, device_type):
    log_message("info", f"Starting verification for device: {device['switchName']} ({device['ipAddress']})")
    client = ssh_connect(device['ipAddress'], device['Credentials']['user'], device['Credentials']['password'])
    if not client:
        log_message("error", f"Unable to connect to device: {device['switchName']} ({device['ipAddress']})")
        return

    interfaces_to_check = extract_interfaces_from_links(device.get('Links', []))
    print(f"Extracted interfaces to check: {interfaces_to_check}")

    print("Checking QoS configuration...")
    qos_result = check_qos_config(client, device['Credentials']['password'])
    log_message("result", f"QoS Check:{qos_result}")

    log_message("info", "Checking BGP ASN configuration...")
    bgp_result = check_bgp_config(client, device['ASN'], device['Credentials']['password'])
    log_message("result", f"BGP ASN Check: {bgp_result}")

    log_message("info", "Checking BGP neighbors...")
    neighbor_result = check_bgp_neighbors(client, device['Credentials']['password'])
    log_message("result", f"BGP Neighbors Check: {neighbor_result}")

    log_message("info", "Checking BFD configuration...")
    bfd_result = check_bfd_config(client, device['Credentials']['password'])
    log_message("result", f"BFD Check: {bfd_result}")

    log_message("info", "Checking BGP path selection and graceful restart...")
    bgp_result = check_bgp_path_selection_and_graceful_restart(client, device['Credentials']['password'])
    log_message("result", f"BGP Path Selection and Graceful Restart Check: {bgp_result}")

    log_message("info", f"Checking BGP redistribution configuration for {device_type}...")
    bgp_redistribute_result = check_bgp_redistribute(client, device_type, device['Credentials']['password'])
    log_message("result", f"BGP Redistribution Check: {bgp_redistribute_result}")

    log_message("info", "Checking Adaptive Routing configuration...")
    adaptive_routing_result = check_adaptive_routing(client, interfaces_to_check, device['Credentials']['password'])
    log_message("result", f"Adaptive Routing Check: {adaptive_routing_result}")

    log_message("info", "Checking loopback IP configuration...")
    loopback_result = check_loopback_ip(client, config['IPv4Pool']['Loopback'], device['Credentials']['password'])
    log_message("result", f"Loopback IP Check: {loopback_result}")

    log_message("info", "Checking interface IPs...")
    interface_ip_result = check_interface_ips(client, config['IPv4Pool'].get('LeafSpine', "40.0.0.0/24"), interfaces_to_check, device['Credentials']['password'])
    log_message("result", f"Interface IPs Check: {interface_ip_result}")

    print("Checking interface status...")
    interface_status_result = check_interface_status(client, interfaces_to_check, device['Credentials']['password'])
    log_message("result", f"Interface Status Check:\n{interface_status_result}")

    log_message("info", "Checking BGP peer groups...")
    peer_group_result = check_bgp_peer_groups(client, device['Credentials']['password'])
    log_message("result", f"BGP Peer Groups Check: {peer_group_result}")

    log_message("info", f"Completed verification for device: {device['switchName']} ({device['ipAddress']})\n")
    client.close()

def verify_host(host, config):
    log_message("info", f"Checking host: {host['hostName']} ({host['ipAddress']})")
    client = ssh_connect(host['ipAddress'], host['Credentials']['user'], host['Credentials']['password'])
    if not client:
        log_message("error", f"Failed to connect to host: {host['hostName']} ({host['ipAddress']})")
        return

    interfaces_to_check = extract_interfaces_from_links(host.get('Links', []))
    expected_routes = host.get('ExpectedRoutes', [])
    host_pool = host.get('IPv4Pool', config['IPv4Pool'].get('Host', ''))
    if not host_pool:
        log_message("error", f"Missing or invalid IPv4Pool for host: {host['hostName']} ({host['ipAddress']})")
        client.close()
        return

    # Check Host Interface IPs
    log_message("info", "Checking host interface IPs...")
    interface_ip_result = check_host_interface_ips(client, interfaces_to_check, host_pool, host['Credentials']['password'])
    log_message("result", f"Host Interface IPs Check: {interface_ip_result}")

    # Check Host Routes
    log_message("info", "Checking host routes...")
    route_result = check_host_routes(client, expected_routes, host['Credentials']['password'])
    log_message("result", f"Host Routes Check: {route_result}")

    # Check Host MTU
    log_message("info", "Checking host MTU...")
    mtu_result = check_host_mtu(client, interfaces_to_check)
    log_message("result", f"Host MTU Check: {mtu_result}")

    # Check Hostname
    log_message("info", "Checking host hostname...")
    hostname_result = check_host_hostname(client, host['hostName'])
    log_message("result", f"Host Hostname Check: {hostname_result}")

    client.close()
    log_message("info", f"Finished checking host: {host['hostName']} ({host['ipAddress']})\n")

def main(yaml_file):
    log_message("info", f"Loading configuration from {yaml_file}...")
    config = load_yaml(yaml_file)

# Verify network connectivity (ping across all devices)
    log_message("info", "Starting network connectivity verification...")
    ping_results = verify_network_connectivity(yaml_file)
    for source, pings in ping_results.items():
        log_message("info", f"Ping results from {source}:")
        for target, result in pings:
            log_message("result", f"  To {target}: {result}")

    for category in ['Spine', 'Leaf', 'Tor']:
        devices = config.get('Connectivity', {}).get(category, [])
        log_message("info", f"Found {len(devices)} devices in category '{category}'")
        for device in devices:
            device_type = category.lower()
            verify_device(device, config, device_type)

    hosts = config.get('Connectivity', {}).get('Host', [])
    log_message("info", f"Found {len(hosts)} hosts")
    for host in hosts:
        verify_host(host, config)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify_cumulus.py <config.yaml>")
        sys.exit(1)
    main(sys.argv[1])
