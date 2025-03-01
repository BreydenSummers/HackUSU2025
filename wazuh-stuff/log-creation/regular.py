#!/usr/bin/env python3
import random
import time
import socket
import argparse
import sys
from datetime import datetime, timedelta

# Define sections and their device types
SECTIONS = {
    "purchasing": ["terminal", "scanner", "inventory-system"],
    "manufacturing": ["cnc", "mill", "press", "quality-check", "laser-cutter"],
    "assembly": ["robot-arm", "conveyor", "testing-station", "vision-system"],
    "packing": ["machine", "label-printer", "scanner", "weight-check"],
    "warehouse": [
        "forklift",
        "rack-system",
        "inventory-scanner",
        "sorting-system",
        "thermal-monitor",
    ],
    "shipping": [
        "label-system",
        "scanner",
        "conveyor",
        "weight-scale",
        "tracking-system",
    ],
}

# Syslog facilities
FACILITIES = {
    "kern": 0,  # kernel messages
    "user": 1,  # user-level messages
    "mail": 2,  # mail system
    "daemon": 3,  # system daemons
    "auth": 4,  # security/authorization messages
    "syslog": 5,  # messages generated internally by syslogd
    "lpr": 6,  # line printer subsystem
    "news": 7,  # network news subsystem
    "uucp": 8,  # UUCP subsystem
    "cron": 9,  # clock daemon
    "authpriv": 10,  # security/authorization messages (private)
    "ftp": 11,  # FTP daemon
    "local0": 16,  # local use 0
    "local1": 17,  # local use 1
    "local2": 18,  # local use 2
    "local3": 19,  # local use 3
    "local4": 20,  # local use 4
    "local5": 21,  # local use 5
    "local6": 22,  # local use 6
    "local7": 23,  # local use 7
}

# Syslog severities
SEVERITIES = {
    "emerg": 0,  # emergency - system is unusable
    "alert": 1,  # alert - action must be taken immediately
    "crit": 2,  # critical - critical conditions
    "err": 3,  # error - error conditions
    "warning": 4,  # warning - warning conditions
    "notice": 5,  # notice - normal but significant condition
    "info": 6,  # informational - informational messages
    "debug": 7,  # debug - debug-level messages
}

# System services and processes that commonly appear in syslog
PROCESSES = {
    "kernel": ["kernel", "klogd"],
    "system": ["systemd", "init", "cron", "ntpd", "sshd", "rsyslogd", "supervisord"],
    "security": ["sudo", "su", "sshd", "fail2ban", "pam", "polkit"],
    "hardware": ["kernel", "udevd", "acpid", "smartd", "thermald"],
    "network": [
        "dhclient",
        "dhcpcd",
        "networkmanager",
        "named",
        "dnsmasq",
        "wpa_supplicant",
    ],
}

# Common log patterns
LOG_PATTERNS = {
    # System boot and shutdown
    "system": [
        "Starting system",
        "System halted",
        "Reached target Multi-User System",
        "Starting daily activities...",
        "Starting cleanup of temporary directories...",
        "Stopped target system-update",
        "Starting update UTMP about System Reboot...",
        "Started update UTMP about System Reboot.",
        "Starting Rotate log files...",
        "Started Rotate log files.",
        "Startup finished in {boot_time}s.",
    ],
    # Process-related
    "process": [
        "Process {pid} ({process}) started",
        "Process {pid} ({process}) exited with status {exit_code}",
        "Process {pid} ({process}) killed (signal {signal})",
        "Process {pid} ({process}) terminated",
        "Child process {pid} exited with code {exit_code}",
        "{process}[{pid}]: Started",
        "{process}[{pid}]: Stopped",
        "{process}[{pid}]: Restarted",
        "Received SIGHUP, reloading configuration",
        "Out of memory: Killed process {pid} ({process})",
    ],
    # Authentication
    "auth": [
        "FAILED su for {user} by {source_user}",
        "Successful su for {user} by {source_user}",
        "session opened for user {user} by (uid={uid})",
        "session closed for user {user}",
        "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={remote_ip}",
        "Failed password for {user} from {remote_ip} port {port} ssh2",
        "Accepted password for {user} from {remote_ip} port {port} ssh2",
        "User {user} not in sudoers",
        "New user {user} added",
        "Password changed for user {user}",
    ],
    # Disk/filesystem
    "disk": [
        "Filesystem {filesystem} has {used_percent}% used space",
        "Running filesystem check on {device}",
        "Filesystem check completed: {status}",
        "I/O error on device {device}, logical block {block}",
        "Device {device} read-only filesystem remounted",
        "Write protect on {device}",
        "Disk space alert: {used_percent}% used on {filesystem}",
        "Scanning for bad blocks on {device}",
        "New disk detected: {device}",
        "Disk {device} has been removed",
    ],
    # Network
    "network": [
        "Interface {interface} up",
        "Interface {interface} down",
        "DHCP address {ip} obtained for interface {interface}",
        "Connection established to {remote_ip}:{port}",
        "Connection closed with {remote_ip}:{port}",
        "Failed to resolve hostname {hostname}",
        "Packet loss detected on interface {interface}",
        "Network is unreachable",
        "MAC address {mac} detected on network",
        "IP conflict detected: {ip} with {mac}",
    ],
    # CPU/Memory
    "resource": [
        "CPU usage: {cpu_percent}%",
        "Memory usage: {mem_percent}%",
        "Swap usage: {swap_percent}%",
        "Load average: {load1} {load5} {load15}",
        "High CPU load detected: {load1}",
        "Low memory condition: {mem_available}MB available",
        "OOM killer activated",
        "Process {process}[{pid}] using excessive CPU: {cpu_percent}%",
        "Process {process}[{pid}] using excessive memory: {mem_mb}MB",
        "Thermal throttling activated: CPU temperature {cpu_temp}°C",
    ],
    # Services
    "service": [
        "Service {service} starting",
        "Service {service} started",
        "Service {service} stopping",
        "Service {service} stopped",
        "Service {service} failed to start: {reason}",
        "Service {service} entered failed state",
        "Restarting service {service}",
        "Service {service} reload",
        "Watchdog timeout for service {service}",
        "Service {service} state changed: {old_state} -> {new_state}",
    ],
    # Cron jobs
    "cron": [
        "({user}) CMD ({command})",
        "Job {job_id} started for user {user}",
        "Job {job_id} completed for user {user}",
        "Job {job_id} failed: {error}",
        "CRON[{pid}]: ({user}) CMD ({command})",
        "cron.daily: Starting {script}",
        "cron.daily: Finished {script}",
        "cron.hourly job {job} started",
        "cron.weekly: Running {script}",
        "cron.monthly: Starting {script}",
    ],
    # Updates
    "update": [
        "Starting system update",
        "System update completed successfully",
        "Package {package} upgraded from {old_version} to {new_version}",
        "Update failed: {reason}",
        "New kernel installed: {kernel_version}",
        "Applying security patches",
        "Downloading package {package}",
        "Verifying package integrity: {package}",
        "Reboot required to complete updates",
        "Update service started",
    ],
    # Hardware
    "hardware": [
        "Device {device} detected",
        "Device {device} removed",
        "CPU temperature: {cpu_temp}°C",
        "Fan speed: {fan_speed} RPM",
        "Battery at {battery_percent}%, {battery_status}",
        "USB device {usb_device} connected to port {usb_port}",
        "SMART warning: {device} - {smart_message}",
        "Hardware error detected: {hw_error}",
        "Power supply {psu} status: {psu_status}",
        "Memory module {dimm} error correction",
    ],
    # Custom section-specific messages
    "purchasing": [
        "Inventory system database synchronized",
        "Order #{order_id} processed",
        "Purchase requisition #{req_id} approved",
        "Vendor connection timeout after {timeout}ms",
        "Inventory level updated: SKU #{sku_id}",
    ],
    "manufacturing": [
        "Production batch #{batch_id} started",
        "Machine calibration complete",
        "Temperature reading: {temp}°C",
        "Pressure sensor: {pressure} PSI",
        "Quality check completed for batch #{batch_id}",
    ],
    "assembly": [
        "Assembly operation #{op_id} completed",
        "Component #{component_id} installed",
        "Testing cycle initiated for unit #{unit_id}",
        "Vision system check passed for unit #{unit_id}",
        "Conveyor system status: {status}",
    ],
    "packing": [
        "Unit #{unit_id} packed",
        "Label printed for shipment #{shipment_id}",
        "Package weight check: {weight}kg",
        "Barcode scan complete for unit #{unit_id}",
        "Packing material inventory: {level}",
    ],
    "warehouse": [
        "Inventory updated: SKU #{sku_id}",
        "Item moved to location {location}",
        "Temperature in zone {zone}: {temp}°C",
        "Humidity in zone {zone}: {humidity}%",
        "Stock level alert: item #{item_id}",
    ],
    "shipping": [
        "Shipment #{shipment_id} ready",
        "Tracking number #{tracking_id} generated",
        "Package #{package_id} weighed: {weight}kg",
        "Shipping label applied to package #{package_id}",
        "Shipment #{shipment_id} loaded",
    ],
}

# Error messages by category
ERROR_PATTERNS = {
    "system": [
        "System error: {error_code}",
        "Critical system failure: {component}",
        "Kernel panic - not syncing: {panic_reason}",
        "Unable to mount {filesystem} on {device}",
        "Failed to start {service}: {reason}",
    ],
    "process": [
        "Process {pid} crashed with signal {signal}",
        "Segmentation fault at address {address}",
        "Process {pid} ({process}) used too much memory and was killed",
        "Deadlock detected in process {pid}",
        "Process {pid} timed out and was terminated",
    ],
    "auth": [
        "Authentication failure for user {user} from {remote_ip}",
        "Too many failed login attempts for {user}, account locked",
        "Possible break-in attempt from {remote_ip}",
        "Permission denied to {user} for {resource}",
        "Invalid authentication token",
    ],
    "disk": [
        "Disk {device} is full",
        "I/O error on device {device}",
        "Read-only file system error on {device}",
        "Corrupted superblock on {device}",
        "Bad blocks detected on {device}",
    ],
    "network": [
        "Network connection lost on interface {interface}",
        "DNS resolution failure for {hostname}",
        "Connection timeout to {remote_ip}:{port}",
        "Network interface {interface} error: {error}",
        "SSL certificate validation failed for {hostname}",
    ],
    "resource": [
        "Out of memory: killed process {pid}",
        "CPU overheating: {cpu_temp}°C",
        "System overload, load average: {load1}",
        "Swap space critically low: {swap_percent}%",
        "Resource limit reached for {resource}",
    ],
    "service": [
        "Service {service} failed: {reason}",
        "Service {service} crashed after {uptime} seconds",
        "Failed to restart {service} after {attempts} attempts",
        "Service {service} dependency failure: {dependency}",
        "Timeout waiting for {service} to start",
    ],
    "purchasing": [
        "Failed to connect to vendor API",
        "Inventory database synchronization error",
        "Order validation failed: {reason}",
        "Payment processing error for order #{order_id}",
        "SKU #{sku_id} not found in database",
    ],
    "manufacturing": [
        "Machine emergency stop triggered",
        "Material feed jam detected",
        "Temperature exceeded threshold: {temp}°C",
        "Calibration failed",
        "Production batch #{batch_id} quality check failed",
    ],
    "assembly": [
        "Robot arm movement error",
        "Component mismatch detected",
        "Vision system calibration failed",
        "Conveyor motor overheated",
        "Assembly operation #{op_id} failed: {reason}",
    ],
    "packing": [
        "Label printer error: {error}",
        "Weight check failed for unit #{unit_id}",
        "Barcode scan failed: {reason}",
        "Packaging material jam",
        "Automatic packing sequence aborted",
    ],
    "warehouse": [
        "Inventory discrepancy for SKU #{sku_id}",
        "Temperature alarm in zone {zone}: {temp}°C",
        "Automated storage retrieval system error",
        "Rack system overload detected",
        "Forklift position error: {error_code}",
    ],
    "shipping": [
        "Carrier API connection failure",
        "Tracking number generation failed",
        "Shipment weight exceeds limit: {weight}kg",
        "Invalid shipping address for order #{order_id}",
        "Shipping label application failed",
    ],
}


# Generate a random hostname for a given section
def get_random_device(section):
    device_type = random.choice(SECTIONS.get(section, ["server"]))
    device_num = random.randint(1, 9)
    return f"{section}-{device_type}-{device_num}"


# Generate a set of unique hostnames across all sections
def generate_devices(count=30):
    devices = []
    sections_list = list(SECTIONS.keys())

    # Ensure at least one device per section
    for section in sections_list:
        devices.append((section, get_random_device(section)))

    # Add remaining devices randomly distributed across sections
    while len(devices) < count:
        section = random.choice(sections_list)
        device = get_random_device(section)
        # Avoid exact duplicates
        if (section, device) not in devices:
            devices.append((section, device))

    return devices


# Fill template variables with realistic values
def fill_template(message, section=None):
    result = message

    # System variables
    if "{pid}" in result:
        result = result.replace("{pid}", str(random.randint(1, 65535)))
    if "{process}" in result:
        category = random.choice(list(PROCESSES.keys()))
        result = result.replace("{process}", random.choice(PROCESSES[category]))
    if "{exit_code}" in result:
        # Usually 0 for success, non-zero for errors
        if "error" in result.lower() or "fail" in result.lower():
            result = result.replace("{exit_code}", str(random.randint(1, 255)))
        else:
            result = result.replace("{exit_code}", "0")
    if "{signal}" in result:
        # Common signals: SIGTERM (15), SIGKILL (9), SIGSEGV (11)
        signals = ["15", "9", "11", "6", "1"]
        result = result.replace("{signal}", random.choice(signals))
    if "{boot_time}" in result:
        result = result.replace("{boot_time}", str(random.uniform(8.5, 45.3))[:4])

    # Auth variables
    if "{user}" in result:
        users = [
            "root",
            "admin",
            "www-data",
            "nobody",
            "apache",
            "mysql",
            "postgres",
            "jenkins",
            "ubuntu",
            "sysadmin",
            "operator",
        ]
        result = result.replace("{user}", random.choice(users))
    if "{source_user}" in result:
        users = ["root", "admin", "sysadmin", "operator", "ubuntu"]
        result = result.replace("{source_user}", random.choice(users))
    if "{uid}" in result:
        uids = {"root": 0, "admin": 1000, "www-data": 33, "nobody": 65534}
        user = result.split("user ")[1].split(" ")[0] if "user " in result else "admin"
        result = result.replace(
            "{uid}", str(uids.get(user, random.randint(1000, 5000)))
        )
    if "{remote_ip}" in result:
        result = result.replace(
            "{remote_ip}", f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
        )
    if "{port}" in result:
        result = result.replace("{port}", str(random.randint(10000, 65000)))

    # Disk/filesystem variables
    if "{device}" in result:
        devices = [
            f"sda{random.randint(1,4)}",
            f"nvme0n{random.randint(1,2)}p{random.randint(1,3)}",
            f"xvd{random.choice('abcdef')}",
            f"md{random.randint(0,3)}",
        ]
        result = result.replace("{device}", random.choice(devices))
    if "{filesystem}" in result:
        filesystems = ["/", "/home", "/var", "/tmp", "/usr", "/var/log", "/opt"]
        result = result.replace("{filesystem}", random.choice(filesystems))
    if "{used_percent}" in result:
        if "alert" in result.lower() or "crit" in result.lower():
            result = result.replace("{used_percent}", str(random.randint(90, 99)))
        else:
            result = result.replace("{used_percent}", str(random.randint(40, 85)))
    if "{block}" in result:
        result = result.replace("{block}", hex(random.randint(1000, 100000)))
    if "{status}" in result:
        statuses = ["clean", "errors corrected", "needs manual repair"]
        result = result.replace("{status}", random.choice(statuses))

    # Network variables
    if "{interface}" in result:
        interfaces = ["eth0", "ens3", "ens5", "wlan0", "enp1s0", "enp0s3"]
        result = result.replace("{interface}", random.choice(interfaces))
    if "{ip}" in result:
        result = result.replace(
            "{ip}", f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
        )
    if "{hostname}" in result:
        hostnames = [
            "server1.local",
            "db.example.com",
            "app-server",
            "backend.internal",
            "monitor.example.net",
            "proxy.local",
        ]
        result = result.replace("{hostname}", random.choice(hostnames))
    if "{mac}" in result:
        mac = ":".join(["%02x" % random.randint(0, 255) for _ in range(6)])
        result = result.replace("{mac}", mac)

    # Resource variables
    if "{cpu_percent}" in result:
        if "excessive" in result or "high" in result:
            result = result.replace("{cpu_percent}", str(random.randint(85, 100)))
        else:
            result = result.replace("{cpu_percent}", str(random.randint(5, 60)))
    if "{mem_percent}" in result:
        if "low" in result:
            result = result.replace("{mem_percent}", str(random.randint(85, 98)))
        else:
            result = result.replace("{mem_percent}", str(random.randint(30, 70)))
    if "{swap_percent}" in result:
        if "crit" in result:
            result = result.replace("{swap_percent}", str(random.randint(80, 95)))
        else:
            result = result.replace("{swap_percent}", str(random.randint(5, 40)))
    if "{load1}" in result:
        if "high" in result:
            load1 = random.uniform(4.0, 20.0)
        else:
            load1 = random.uniform(0.1, 3.0)
        result = result.replace("{load1}", f"{load1:.2f}")
    if "{load5}" in result and "{load15}" in result:
        # Check if "load average:" exists in the string before trying to split
        if "load average:" in result:
            try:
                load1 = float(result.split("load average: ")[1].split(" ")[0])
                load5 = max(0.1, random.uniform(load1 * 0.7, load1 * 1.2))
                load15 = max(0.1, random.uniform(load5 * 0.6, load5 * 1.1))
            except (IndexError, ValueError):
                # Fallback values if parsing fails
                load1 = random.uniform(0.1, 3.0)
                load5 = max(0.1, random.uniform(load1 * 0.7, load1 * 1.2))
                load15 = max(0.1, random.uniform(load5 * 0.6, load5 * 1.1))
        else:
            # Generate reasonable values if "load average:" isn't in the string
            load1 = random.uniform(0.1, 3.0)
            load5 = max(0.1, random.uniform(load1 * 0.7, load1 * 1.2))
            load15 = max(0.1, random.uniform(load5 * 0.6, load5 * 1.1))

        result = result.replace("{load5}", f"{load5:.2f}")
        result = result.replace("{load15}", f"{load15:.2f}")
    if "{mem_available}" in result:
        if "low" in result:
            result = result.replace("{mem_available}", str(random.randint(50, 200)))
        else:
            result = result.replace("{mem_available}", str(random.randint(500, 4000)))
    if "{mem_mb}" in result:
        if "excessive" in result:
            result = result.replace("{mem_mb}", str(random.randint(1000, 8000)))
        else:
            result = result.replace("{mem_mb}", str(random.randint(50, 500)))
    if "{cpu_temp}" in result:
        if "throttling" in result or "overheat" in result:
            result = result.replace("{cpu_temp}", str(random.randint(85, 105)))
        else:
            result = result.replace("{cpu_temp}", str(random.randint(40, 75)))

    # Service variables
    if "{service}" in result:
        services = [
            "nginx",
            "apache2",
            "mysql",
            "postgresql",
            "mongodb",
            "redis",
            "elasticsearch",
            "rabbitmq",
            "docker",
            "kubelet",
            "containerd",
        ]
        result = result.replace("{service}", random.choice(services))
    if "{reason}" in result:
        reasons = [
            "configuration error",
            "missing dependency",
            "resource unavailable",
            "permission denied",
            "timeout",
            "network unreachable",
        ]
        result = result.replace("{reason}", random.choice(reasons))
    if "{old_state}" in result and "{new_state}" in result:
        states = ["running", "stopped", "starting", "stopping", "failed", "exited"]
        old = random.choice(states)
        # Make sure new state is different from old
        new = random.choice([s for s in states if s != old])
        result = result.replace("{old_state}", old)
        result = result.replace("{new_state}", new)

    # Cron variables
    if "{command}" in result:
        commands = [
            "/usr/bin/find /tmp -type f -mtime +7 -delete",
            "/usr/local/bin/backup.sh",
            "/bin/systemctl restart apache2",
            "python3 /usr/local/bin/cleanup.py",
            "/usr/bin/apt-get update",
        ]
        result = result.replace("{command}", random.choice(commands))
    if "{job_id}" in result:
        result = result.replace("{job_id}", str(random.randint(1, 999)))
    if "{script}" in result:
        scripts = [
            "logrotate",
            "backup",
            "cleanup",
            "updatedb",
            "security-updates",
            "scan",
        ]
        result = result.replace("{script}", random.choice(scripts))
    if "{job}" in result and not "{job_id}" in result:
        jobs = ["backup", "cleanup", "monitor", "report", "maintenance"]
        result = result.replace("{job}", random.choice(jobs))
    if "{error}" in result:
        errors = [
            "command not found",
            "permission denied",
            "non-zero exit status",
            "timeout exceeded",
            "resource temporarily unavailable",
        ]
        result = result.replace("{error}", random.choice(errors))

    # Update variables
    if "{package}" in result:
        packages = [
            "linux-image",
            "openssl",
            "libc6",
            "nginx",
            "apache2",
            "mysql-server",
            "openssh-server",
            "python3",
            "ca-certificates",
        ]
        result = result.replace("{package}", random.choice(packages))
    if "{old_version}" in result and "{new_version}" in result:
        old_major = random.randint(1, 5)
        old_minor = random.randint(0, 9)
        old_patch = random.randint(0, 20)
        old_version = f"{old_major}.{old_minor}.{old_patch}"

        # New version is either a minor or patch update
        update_type = random.choice(["minor", "patch"])
        if update_type == "minor":
            new_version = f"{old_major}.{old_minor + 1}.0"
        else:
            new_version = f"{old_major}.{old_minor}.{old_patch + 1}"

        result = result.replace("{old_version}", old_version)
        result = result.replace("{new_version}", new_version)
    if "{kernel_version}" in result:
        kernel_versions = [
            "5.15.0-58-generic",
            "5.19.0-35-generic",
            "6.1.0-12-amd64",
            "6.2.0-26-generic",
        ]
        result = result.replace("{kernel_version}", random.choice(kernel_versions))

    # Hardware variables
    if "{fan_speed}" in result:
        result = result.replace("{fan_speed}", str(random.randint(1200, 3600)))
    if "{battery_percent}" in result:
        result = result.replace("{battery_percent}", str(random.randint(1, 100)))
    if "{battery_status}" in result:
        statuses = ["discharging", "charging", "fully charged", "low", "critical"]
        result = result.replace("{battery_status}", random.choice(statuses))
    if "{usb_device}" in result:
        devices = [
            "Kingston_DataTraveler",
            "Logitech_USB_Mouse",
            "ADATA_USB_Flash_Drive",
            "SanDisk_Ultra",
            "Generic_USB_Hub",
        ]
        result = result.replace("{usb_device}", random.choice(devices))
    if "{usb_port}" in result:
        result = result.replace("{usb_port}", str(random.randint(1, 6)))
    if "{smart_message}" in result:
        smart_msgs = [
            "Read error rate above threshold",
            "Reallocated sectors count increased",
            "Spin retry count threshold exceeded",
            "Offline uncorrectable sector count",
            "Self-test failed",
        ]
        result = result.replace("{smart_message}", random.choice(smart_msgs))
    if "{hw_error}" in result:
        hw_errors = [
            "RAM ECC error",
            "PCIe link failure",
            "CMOS checksum invalid",
            "CPU thermal throttling",
            "GPU memory error",
        ]
        result = result.replace("{hw_error}", random.choice(hw_errors))
    if "{psu}" in result:
        result = result.replace(
            "{psu}", random.choice(["primary", "secondary", "redundant"])
        )
    if "{psu_status}" in result:
        statuses = [
            "normal",
            "warning",
            "critical",
            "over temperature",
            "input voltage low",
        ]
        result = result.replace("{psu_status}", random.choice(statuses))
    if "{dimm}" in result:
        result = result.replace(
            "{dimm}", f"DIMM_{random.choice(['A1', 'A2', 'B1', 'B2'])}"
        )

    # Section-specific variables
    if section:
        if "{order_id}" in result:
            result = result.replace("{order_id}", str(random.randint(100000, 999999)))
        if "{req_id}" in result:
            result = result.replace("{req_id}", str(random.randint(10000, 99999)))
        if "{timeout}" in result:
            result = result.replace("{timeout}", str(random.randint(1000, 30000)))
        if "{sku_id}" in result:
            result = result.replace("{sku_id}", f"SKU-{random.randint(1000, 9999)}")
        if "{batch_id}" in result:
            result = result.replace("{batch_id}", str(random.randint(1000, 9999)))
        if "{temp}" in result:
            if "exceeded" in result or "alarm" in result:
                result = result.replace("{temp}", str(random.randint(85, 100)))
            else:
                result = result.replace("{temp}", str(random.randint(20, 30)))
        if "{pressure}" in result:
            result = result.replace("{pressure}", str(random.randint(30, 100)))
        if "{op_id}" in result:
            result = result.replace("{op_id}", str(random.randint(100, 999)))
        if "{component_id}" in result:
            result = result.replace("{component_id}", str(random.randint(1000, 9999)))
        if "{unit_id}" in result:
            result = result.replace("{unit_id}", str(random.randint(10000, 99999)))
        if "{status}" in result and not "{psu_status}" in result:
            statuses = ["normal", "running", "paused", "maintenance", "error"]
            result = result.replace("{status}", random.choice(statuses))
        if "{shipment_id}" in result:
            result = result.replace(
                "{shipment_id}", str(random.randint(100000, 999999))
            )
        if "{weight}" in result:
            if "exceeds" in result:
                result = result.replace("{weight}", str(random.randint(50, 100)))
            else:
                result = result.replace("{weight}", f"{random.uniform(1.5, 25.0):.1f}")
        if "{level}" in result:
            result = result.replace("{level}", f"{random.randint(10, 95)}%")
        if "{location}" in result:
            result = result.replace(
                "{location}",
                f"{random.choice('ABCDEFGH')}{random.randint(1, 50)}-{random.randint(1, 20)}",
            )
        if "{zone}" in result:
            result = result.replace("{zone}", f"{random.choice('ABCDEF')}")
        if "{humidity}" in result:
            result = result.replace("{humidity}", str(random.randint(30, 70)))
        if "{item_id}" in result:
            result = result.replace("{item_id}", str(random.randint(1000, 9999)))
        if "{tracking_id}" in result:
            result = result.replace(
                "{tracking_id}", f"TRK{random.randint(1000000, 9999999)}"
            )
        if "{package_id}" in result:
            result = result.replace(
                "{package_id}", f"PKG-{random.randint(100000, 999999)}"
            )
        if "{error_code}" in result:
            result = result.replace("{error_code}", f"E{random.randint(1000, 9999)}")

    return result


# Generate a log message for a specific device
def generate_log(hostname, section, timestamp=None):
    # Determine log type and severity
    is_error = random.random() < 0.15  # 15% chance of error logs

    if is_error:
        severity = (
            random.choice(["err", "warning", "crit"])
            if random.random() < 0.8
            else random.choice(["alert", "emerg"])
        )
        pattern_category = random.choice(
            [
                section,
                "system",
                "process",
                "auth",
                "disk",
                "network",
                "resource",
                "service",
            ]
        )
        if pattern_category in ERROR_PATTERNS:
            pattern = random.choice(ERROR_PATTERNS[pattern_category])
        else:
            pattern = random.choice(ERROR_PATTERNS["system"])
    else:
        severity = random.choices(
            ["info", "notice", "debug", "warning"], weights=[70, 15, 10, 5], k=1
        )[0]

        # Determine log pattern category
        if random.random() < 0.7 and section in LOG_PATTERNS:
            # 70% chance of using section-specific message
            pattern_category = section
        else:
            # 30% chance of using general system message
            pattern_category = random.choice(
                [
                    "system",
                    "process",
                    "auth",
                    "disk",
                    "network",
                    "resource",
                    "service",
                    "cron",
                ]
            )

        if pattern_category in LOG_PATTERNS:
            pattern = random.choice(LOG_PATTERNS[pattern_category])
        else:
            pattern = random.choice(LOG_PATTERNS["system"])

    # Choose facility based on log type
    if pattern_category in ["auth", "security"]:
        facility = "auth"
    elif pattern_category in ["cron"]:
        facility = "cron"
    elif pattern_category in ["system"]:
        facility = random.choice(["daemon", "syslog"])
    elif pattern_category in ["disk", "hardware"]:
        facility = random.choice(["kern", "daemon"])
    else:
        facility = random.choice(["user", "local0", "local1", "local2"])

    # Generate timestamp if not provided
    if timestamp is None:
        timestamp = datetime.now()

    # Format timestamp for syslog
    timestamp_str = timestamp.strftime("%b %d %H:%M:%S")

    # Choose process name
    if section in [
        "purchasing",
        "manufacturing",
        "assembly",
        "packing",
        "warehouse",
        "shipping",
    ]:
        process = f"{section}-agent"
    else:
        category = random.choice(list(PROCESSES.keys()))
        process = random.choice(PROCESSES[category])

    # Generate a process ID
    pid = random.randint(1, 65535)

    # Fill in template variables
    message = fill_template(pattern, section)

    # Calculate priority value (facility * 8 + severity)
    priority = (FACILITIES.get(facility, 1) * 8) + SEVERITIES.get(severity, 6)

    # Format the final log message
    log_message = f"<{priority}>{timestamp_str} {hostname} {process}[{pid}]: {message}"

    return log_message


# Send log to Wazuh
def send_log(log_message, target_host, target_port):
    try:
        # Send via UDP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bytes_sent = sock.sendto(
            log_message.encode("utf-8"), (target_host, target_port)
        )
        return True, bytes_sent
    except Exception as e:
        print(f"Error sending log: {e}")
        return False, 0


# Main function
def main():
    parser = argparse.ArgumentParser(
        description="Generate dummy syslog messages for Wazuh"
    )
    parser.add_argument(
        "--host", default="localhost", help="Wazuh server hostname or IP"
    )
    parser.add_argument("--port", type=int, default=514, help="Wazuh syslog port")
    parser.add_argument(
        "--devices", type=int, default=30, help="Number of unique devices to simulate"
    )
    parser.add_argument(
        "--rate", type=float, default=1.0, help="Log generation rate (logs per second)"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=0,
        help="Duration to run in minutes (0 = run indefinitely)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="File to write logs to instead of sending to Wazuh",
    )
    parser.add_argument("--verbose", action="store_true", help="Print logs to stdout")
    parser.add_argument(
        "--test-connection",
        action="store_true",
        help="Test connection to Wazuh server and exit",
    )

    args = parser.parse_args()

    # Test connection if requested
    if args.test_connection:
        print(f"Testing connection to Wazuh server at {args.host}:{args.port}...")
        try:
            # Try to resolve hostname
            try:
                ip_address = socket.gethostbyname(args.host)
                print(f"✓ Hostname {args.host} resolves to {ip_address}")
            except socket.gaierror:
                print(f"✗ Could not resolve hostname {args.host}")
                return

            # Try to create a socket and send test message
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            test_msg = f"<14>Mar 01 12:00:00 test-device syslog-test[12345]: Test message from wazuh-dummy-logs"
            bytes_sent = sock.sendto(test_msg.encode("utf-8"), (args.host, args.port))
            print(f"✓ Successfully sent {bytes_sent} bytes to {args.host}:{args.port}")
            print(
                "Note: This does not guarantee logs will be processed by Wazuh, only that network connectivity exists."
            )
            print("If logs are not appearing in Wazuh, please check:")
            print("1. Wazuh server is configured to listen on UDP port {args.port}")
            print("2. Firewall rules allow traffic to this port")
            print("3. Wazuh agent is properly configured to collect syslog messages")
            return
        except Exception as e:
            print(f"✗ Connection test failed: {e}")
            return

    print(f"Generating logs for {args.devices} devices...")
    devices = generate_devices(args.devices)

    # Print device list
    print("\nDevices:")
    for i, (section, hostname) in enumerate(devices, 1):
        print(f"{i:2d}. [{section}] {hostname}")

    # Calculate sleep time between logs
    sleep_time = 1.0 / args.rate

    # Set end time if duration specified
    end_time = None
    if args.duration > 0:
        end_time = datetime.now() + timedelta(minutes=args.duration)
        print(f"\nRunning for {args.duration} minutes (until {end_time})")
    else:
        print("\nRunning indefinitely (press Ctrl+C to stop)")

    # Open output file if specified
    output_file = None
    if args.output:
        output_file = open(args.output, "w")
        print(f"Writing logs to {args.output}")
    else:
        print(f"Sending logs to {args.host}:{args.port}")

    # Counter for logs
    log_count = 0
    sent_count = 0
    bytes_sent_total = 0
    start_time = datetime.now()

    try:
        while True:
            # Check if duration exceeded
            if end_time and datetime.now() > end_time:
                break

            # Choose a random device
            section, hostname = random.choice(devices)

            # Generate log
            log_message = generate_log(hostname, section)
            log_count += 1

            # Output based on configuration
            if args.verbose:
                print(log_message)

            if output_file:
                output_file.write(log_message + "\n")
                output_file.flush()
            else:
                success, bytes_sent = send_log(log_message, args.host, args.port)
                if success:
                    sent_count += 1
                    bytes_sent_total += bytes_sent

            # Sleep until next log
            time.sleep(sleep_time)

            # Print stats every 1000 logs or every 10 seconds, whichever comes first
            if log_count % 1000 == 0 or (
                log_count % 10 == 0
                and (datetime.now() - start_time).total_seconds() >= 10
            ):
                elapsed = (datetime.now() - start_time).total_seconds()
                rate = log_count / elapsed if elapsed > 0 else 0
                if output_file:
                    print(f"Generated {log_count} logs ({rate:.1f} logs/second)")
                else:
                    success_rate = (
                        (sent_count / log_count * 100) if log_count > 0 else 0
                    )
                    print(
                        f"Generated {log_count} logs, sent {sent_count} ({success_rate:.1f}%), {bytes_sent_total/1024:.1f} KB total ({rate:.1f} logs/second)"
                    )

    except KeyboardInterrupt:
        print("\nStopped by user")
    finally:
        if output_file:
            output_file.close()

        # Print final stats
        elapsed = (datetime.now() - start_time).total_seconds()
        rate = log_count / elapsed if elapsed > 0 else 0

        if output_file:
            print(
                f"\nGenerated {log_count} logs in {elapsed:.1f} seconds ({rate:.1f} logs/second)"
            )
        else:
            success_rate = (sent_count / log_count * 100) if log_count > 0 else 0
            print(
                f"\nGenerated {log_count} logs, sent {sent_count} ({success_rate:.1f}%), {bytes_sent_total/1024:.1f} KB total in {elapsed:.1f} seconds ({rate:.1f} logs/second)"
            )


if __name__ == "__main__":
    main()

