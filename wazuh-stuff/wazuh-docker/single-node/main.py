#!/usr/bin/env python3
import os
import json
import subprocess
import uuid
import logging
import time
import bcrypt
import shutil
from pathlib import Path
from flask import Flask, request, jsonify

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("docker-deploy-api")

app = Flask(__name__)


def hash_password(password):
    """
    Create a bcrypt hash of the password for internal_users.yml

    Args:
        password (str): The password to hash

    Returns:
        str: Bcrypt hashed password
    """
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12))
    return hashed.decode("utf-8")


def create_ossec_conf():
    """
    Create a custom ossec.conf file with syslog enabled

    Returns:
        str: Path to the created ossec.conf file
    """
    config_content = """<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>smtp.example.wazuh.com</smtp_server>
    <email_from>wazuh@example.wazuh.com</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
  </global>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
  </remote>

  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>0.0.0.0/0</allowed-ips>
  </remote>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <command>
    <name>disable-account</name>
    <executable>disable-account</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>restart-wazuh</name>
    <executable>restart-wazuh</executable>
  </command>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>host-deny</name>
    <executable>host-deny</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>route-null</name>
    <executable>route-null</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>win_route-null</name>
    <executable>route-null.exe</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>
</ossec_config>
"""
    # Create directory for ossec config if it doesn't exist
    os.makedirs("config/wazuh_cluster", exist_ok=True)

    # Write the config to a file
    config_path = "config/wazuh_cluster/ossec.conf"
    with open(config_path, "w") as f:
        f.write(config_content)

    logger.info(f"Created custom ossec.conf at {config_path}")
    return config_path


def update_internal_users_file(compose_dir, password):
    """
    Update the internal_users.yml file with the hashed password

    Args:
        compose_dir (str): Directory containing the docker-compose.yml
        password (str): Password to set for the 'user' account

    Returns:
        bool: True if successful, False otherwise
    """
    # Use the specific path you've identified
    internal_users_path = os.path.join(
        compose_dir, "config/wazuh_indexer/internal_users.yml"
    )

    try:
        # Check if the directory exists, create it if not
        os.makedirs(os.path.dirname(internal_users_path), exist_ok=True)

        # Check if the file exists
        if os.path.exists(internal_users_path):
            # Create a backup of the original file
            backup_path = f"{internal_users_path}.bak"
            shutil.copy2(internal_users_path, backup_path)

            # Read the current file
            with open(internal_users_path, "r") as f:
                content = f.read()
        else:
            # If file doesn't exist, we'll create it with default content
            content = """---
# This is the internal user database
# The hash value is a bcrypt hash and can be generated with plugin/tools/hash.sh

_meta:
  type: "internalusers"
  config_version: 2

# Define your internal users here

kibanaserver:
  hash: "$2a$12$4AcgAt3xwOWadA5s5blL6ev39OXDNhmOesEoo33eZtrq2N0YrU3H."
  reserved: true
  description: "Kibanaserver user"
"""

        # Generate hashed password
        hashed_password = hash_password(password)

        # Look for 'user:' section in the file
        if "user:" in content:
            # Find the user section and replace the hash value
            lines = content.split("\n")
            user_section_found = False
            hash_line_found = False

            for i, line in enumerate(lines):
                if line.strip() == "user:":
                    user_section_found = True
                elif user_section_found and line.strip().startswith("hash:"):
                    lines[i] = f'  hash: "{hashed_password}"'
                    hash_line_found = True
                    break

            # If we found the user section but no hash line, add it
            if user_section_found and not hash_line_found:
                for i, line in enumerate(lines):
                    if line.strip() == "user:":
                        lines.insert(i + 1, f'  hash: "{hashed_password}"')
                        break

            # If we didn't find a user section, add it
            if not user_section_found:
                user_section = f"""
user:
  hash: "{hashed_password}"
  reserved: false
  backend_roles:
  - "admin"
  description: "Admin user"
"""
                lines.append(user_section)

            # Write the updated content back to the file
            with open(internal_users_path, "w") as f:
                f.write("\n".join(lines))
        else:
            # No user section found, add it
            user_section = f"""
user:
  hash: "{hashed_password}"
  reserved: false
  backend_roles:
  - "admin"
  description: "Admin user"
"""
            with open(internal_users_path, "w") as f:
                f.write(content + user_section)

        logger.info(f"Successfully updated password hash in {internal_users_path}")
        return True

    except Exception as e:
        logger.error(f"Error updating internal_users.yml: {str(e)}")
        # Try to restore backup if it exists
        if "backup_path" in locals() and os.path.exists(backup_path):
            shutil.copy2(backup_path, internal_users_path)
        return False


def update_docker_compose_file(compose_file, ossec_conf_path):
    """
    Update docker-compose.yml to use the custom ossec.conf

    Args:
        compose_file (str): Path to the docker-compose.yml file
        ossec_conf_path (str): Path to the custom ossec.conf file

    Returns:
        str: Path to the updated docker-compose file
    """
    try:
        # Read the current docker-compose file
        with open(compose_file, "r") as f:
            compose_content = f.read()

        # Create a backup of the original file
        backup_file = f"{compose_file}.bak"
        with open(backup_file, "w") as f:
            f.write(compose_content)

        # Find and replace the existing ossec.conf mount line
        if "./config/wazuh_cluster" in compose_content:
            # Replace the existing ossec.conf mount line
            ossec_conf_mount_pattern = (
                r"- ./config/wazuh_cluster/[^:]+:/wazuh-config-mount/etc/ossec.conf"
            )
            import re

            updated_content = re.sub(
                ossec_conf_mount_pattern,
                f"- ./{ossec_conf_path}:/wazuh-config-mount/etc/ossec.conf",
                compose_content,
            )

            # Write the updated content back to the file
            updated_file = f"{compose_file}.updated"
            with open(updated_file, "w") as f:
                f.write(updated_content)

            logger.info(f"Updated docker-compose file at {updated_file}")
            return updated_file
        else:
            # If no existing mount is found, we'll keep the original file
            # The container will be modified after startup
            logger.warning(
                "Could not find ossec.conf mount point in docker-compose.yml"
            )
            logger.warning("Will use post-startup container modification instead")
            return compose_file

    except Exception as e:
        logger.error(f"Error updating docker-compose.yml: {str(e)}")
        return compose_file


def setup_environment_variables(base_port, password):
    """
    Set up environment variables for Docker Compose.

    Args:
        base_port (int): The base port provided by the user
        password (str): Password provided by the user

    Returns:
        dict: Dictionary of environment variables
    """
    env_vars = os.environ.copy()

    # Set the ports
    env_vars["PORT"] = str(base_port)  # Dashboard port (5601)
    env_vars["PORT2"] = str(base_port + 1)  # Manager port (1514)
    env_vars["PORT3"] = str(base_port + 2)  # Manager port (1515)
    env_vars["PORT4"] = str(base_port + 3)  # Manager port (514/udp)
    env_vars["PORT5"] = str(base_port + 4)  # Manager port (55000)
    env_vars["PORT6"] = str(base_port + 5)  # Indexer port (9200)

    # The PASSWORD variable is used for INDEXER_PASSWORD in both wazuh.manager and wazuh.dashboard
    env_vars["PASSWORD"] = password

    # For consistent login, we need to add other credentials too
    # These should match the values in the docker-compose file
    env_vars["API_USERNAME"] = "wazuh-wui"
    env_vars["API_PASSWORD"] = "MyS3cr37P450r.*-"
    env_vars["DASHBOARD_USERNAME"] = "kibanaserver"
    env_vars["DASHBOARD_PASSWORD"] = "kibanaserver"
    env_vars["INDEXER_USERNAME"] = "user"

    # Add settings to improve coordination
    env_vars["OPENSEARCH_JAVA_OPTS"] = "-Xms1g -Xmx1g"

    # Add health check settings
    env_vars["HEALTHCHECK_TIMEOUT"] = "120"
    env_vars["STARTUP_WAIT_TIME"] = "60"  # Increased wait time for services to start

    logger.info(f"Environment variables set up with PORT={env_vars['PORT']}")
    return env_vars


def configure_wazuh_container(project_name):
    """
    Configure the Wazuh manager container after it has started
    to ensure syslog is correctly set up.

    Args:
        project_name (str): Docker Compose project name

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Find the Wazuh manager container
        cmd = [
            "docker",
            "ps",
            "--filter",
            f"name={project_name}_wazuh.manager",
            "--format",
            "{{.ID}}",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        container_id = result.stdout.strip()

        if not container_id:
            logger.error(
                f"Could not find Wazuh manager container for project {project_name}"
            )
            return False

        logger.info(f"Found Wazuh manager container: {container_id}")

        # Create the ossec.conf content
        ossec_conf = """<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>smtp.example.wazuh.com</smtp_server>
    <email_from>wazuh@example.wazuh.com</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
  </global>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
  </remote>

  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>0.0.0.0/0</allowed-ips>
  </remote>

  <alerts>
    <log_alert_level>6</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <command>
    <name>disable-account</name>
    <executable>disable-account</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>restart-wazuh</name>
    <executable>restart-wazuh</executable>
  </command>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>host-deny</name>
    <executable>host-deny</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>route-null</name>
    <executable>route-null</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>win_route-null</name>
    <executable>route-null.exe</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>
</ossec_config>"""

        # Write the config to a temporary file
        temp_conf = f"/tmp/ossec.conf.{uuid.uuid4().hex[:8]}"
        with open(temp_conf, "w") as f:
            f.write(ossec_conf)

        # Copy to container
        copy_cmd = [
            "docker",
            "cp",
            temp_conf,
            f"{container_id}:/var/ossec/etc/ossec.conf",
        ]
        subprocess.run(copy_cmd, check=True)

        # Remove temporary file
        os.remove(temp_conf)

        # Restart Wazuh in the container
        restart_cmd = [
            "docker",
            "exec",
            container_id,
            "/var/ossec/bin/wazuh-control",
            "restart",
        ]
        subprocess.run(restart_cmd, check=True)

        # Verify the syslog server is running
        time.sleep(5)  # Give it a moment to restart
        check_cmd = [
            "docker",
            "exec",
            container_id,
            "netstat",
            "-tulpn",
            "|",
            "grep",
            ":514",
        ]
        try:
            check_result = subprocess.run(
                [
                    "docker",
                    "exec",
                    container_id,
                    "bash",
                    "-c",
                    "netstat -tulpn | grep :514",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            logger.info(f"Syslog server is running: {check_result.stdout.strip()}")
            return True
        except subprocess.CalledProcessError:
            logger.warning(
                "Couldn't verify syslog server is running, but configuration was updated"
            )
            return True

    except Exception as e:
        logger.error(f"Error configuring Wazuh container: {str(e)}")
        return False


def start_log_generator(port, host="localhost", rate=20):
    """
    Start the log generator script in the background

    Args:
        port (int): Port to send logs to
        host (str): Hostname to send logs to
        rate (float): Rate of logs per second

    Returns:
        subprocess.Popen: Process object for the running script
    """
    logger.info(
        f"Starting log generator sending to {host}:{port} at {rate} logs/second"
    )

    # Find the path to regular.py
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_script_path = os.path.join(script_dir, "..", "..", "log-creation", "regular.py")

    # Make sure the script exists
    if not os.path.exists(log_script_path):
        logger.warning(f"Log generator script not found at {log_script_path}")
        # Try to find it in the current directory structure
        for root, dirs, files in os.walk(os.path.dirname(script_dir)):
            if "regular.py" in files:
                log_script_path = os.path.join(root, "regular.py")
                logger.info(f"Found log generator script at {log_script_path}")
                break
        else:
            logger.error("Could not find log generator script regular.py")
            return None

    # Make sure the script is executable
    os.chmod(log_script_path, 0o755)

    # Start the script in the background
    cmd = [
        "python3",
        log_script_path,
        "--host",
        host,
        "--port",
        str(port),
        "--rate",
        str(rate),
        "--verbose",  # Show logs on stdout
    ]

    # Create a new process group so it doesn't get terminated when the parent process exits
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        preexec_fn=os.setpgrp,  # Run in a new process group
    )

    # Start a thread to read the stdout/stderr and log it
    def log_output(process):
        for line in iter(process.stdout.readline, ""):
            logger.info(f"Log Generator: {line.strip()}")

    import threading

    log_thread = threading.Thread(target=log_output, args=(process,))
    log_thread.daemon = True  # Thread will exit when main thread exits
    log_thread.start()

    logger.info(f"Log generator started with PID {process.pid}")
    return process


def run_docker_compose(compose_file, env_vars, project_name):
    """
    Run docker-compose with the specified environment variables.

    Args:
        compose_file (str): Path to the docker-compose.yml file
        env_vars (dict): Environment variables to set
        project_name (str): Docker Compose project name for isolation

    Returns:
        tuple: (success, message)
    """
    # Create a dedicated network for this deployment
    network_name = f"{project_name}-network"
    try:
        logger.info(f"Creating dedicated Docker network: {network_name}")
        network_cmd = ["docker", "network", "create", network_name]
        subprocess.run(network_cmd, check=True)

        # Add network name to environment variables
        env_vars["NETWORK_NAME"] = network_name

        # Create custom ossec.conf with syslog enabled
        ossec_conf_path = create_ossec_conf()

        # Try to update docker-compose file
        updated_compose_file = update_docker_compose_file(compose_file, ossec_conf_path)

        # Update internal_users.yml with the hashed password
        compose_dir = os.path.dirname(os.path.abspath(compose_file))
        if not update_internal_users_file(compose_dir, env_vars["PASSWORD"]):
            logger.warning(
                "Could not update internal_users.yml, login may not work correctly"
            )

        # Pull images first to ensure we have the latest
        logger.info("Pulling Docker images...")
        pull_cmd = [
            "docker-compose",
            "-f",
            updated_compose_file,
            "-p",
            project_name,
            "pull",
        ]
        subprocess.run(pull_cmd, env=env_vars, check=True)

        # Start the services
        logger.info(f"Starting services for project {project_name}...")
        cmd = [
            "docker-compose",
            "-f",
            updated_compose_file,
            "-p",
            project_name,
            "up",
            "-d",
        ]
        subprocess.run(cmd, env=env_vars, check=True)

        # Wait for services to initialize
        logger.info("Waiting for services to initialize...")
        time.sleep(int(env_vars.get("STARTUP_WAIT_TIME", 60)))

        # Configure Wazuh container to ensure syslog is enabled
        if (
            updated_compose_file == compose_file
        ):  # If we couldn't update the compose file
            logger.info("Configuring Wazuh container with syslog enabled...")
            configure_wazuh_container(project_name)

        # Get container status to verify
        status_cmd = [
            "docker-compose",
            "-f",
            updated_compose_file,
            "-p",
            project_name,
            "ps",
        ]
        status_result = subprocess.run(
            status_cmd, env=env_vars, check=True, capture_output=True, text=True
        )

        # Start the log generator to automatically send logs to the deployed instance
        syslog_port = int(env_vars["PORT4"])
        log_generator_process = start_log_generator(syslog_port)
        if log_generator_process:
            logger.info(
                f"Log generator successfully started and sending logs to port {syslog_port}"
            )
        else:
            logger.warning("Could not start log generator automatically")

        return True, {
            "status": "success",
            "project_name": project_name,
            "network_name": network_name,
            "ports": {
                "Dashboard (PORT)": f"{env_vars['PORT']} (https)",
                "Manager - OSSEC (PORT2)": env_vars["PORT2"],
                "Manager - Agent enrollment (PORT3)": env_vars["PORT3"],
                "Manager - Syslog (PORT4)": env_vars["PORT4"],
                "Manager - API (PORT5)": env_vars["PORT5"],
                "Indexer (PORT6)": env_vars["PORT6"],
            },
            "credentials": {
                "wazuh_dashboard": {
                    "url": f"https://localhost:{env_vars['PORT']}",
                    "username": "user",  # The default admin username is usually 'user'
                    "password": env_vars["PASSWORD"],  # Using PASSWORD from env_vars
                },
                "wazuh_api": {
                    "username": env_vars["API_USERNAME"],
                    "password": env_vars["API_PASSWORD"],
                },
            },
            "container_status": status_result.stdout,
            "syslog_enabled": True,
            "log_generator": "Running automatically",
            "syslog_usage": f"Logs are being automatically sent to port {env_vars['PORT4']}. To send additional logs, use: python regular.py --host localhost --port {env_vars['PORT4']} --rate 2",
        }
    except subprocess.CalledProcessError as e:
        logger.error(f"Error in Docker operation: {str(e)}")
        error_msg = (
            e.stderr.decode("utf-8") if hasattr(e, "stderr") and e.stderr else str(e)
        )

        # If we created a network but failed in compose, try to clean it up
        try:
            if "network_name" in locals():
                logger.info(f"Cleaning up network {network_name} after failure")
                subprocess.run(["docker", "network", "rm", network_name], check=False)
        except Exception as cleanup_error:
            logger.error(f"Failed to clean up network: {str(cleanup_error)}")

        return False, {
            "status": "error",
            "message": f"Error in Docker operation: {error_msg}",
        }


@app.route("/deploy", methods=["POST"])
def deploy_container():
    """Handle REST request to deploy a new container instance"""
    data = request.json
    logger.info(f"Received deployment request: {json.dumps(data)}")

    # Validate required fields
    if not data or "port" not in data or "password" not in data:
        logger.error("Missing required fields in request")
        return jsonify(
            {"status": "error", "message": "Port and password are required"}
        ), 400

    try:
        port = int(data["port"])
    except ValueError:
        logger.error("Invalid port value")
        return jsonify({"status": "error", "message": "Port must be an integer"}), 400

    password = data["password"]
    compose_file = data.get("compose_file", "docker-compose.yml")

    # Validate port range
    if port < 1024 or port > 60000:
        logger.error(f"Port {port} outside valid range")
        return jsonify(
            {"status": "error", "message": "Port must be between 1024 and 60000"}
        ), 400

    # Check if ports would exceed maximum
    if port + 5 > 65535:
        logger.error(f"Port range would exceed maximum")
        return jsonify(
            {"status": "error", "message": "Port range would exceed maximum port 65535"}
        ), 400

    # Check if compose file exists
    compose_path = Path(compose_file)
    if not compose_path.exists():
        logger.error(f"Docker Compose file '{compose_file}' not found")
        return jsonify(
            {
                "status": "error",
                "message": f"Docker Compose file '{compose_file}' not found",
            }
        ), 404

    # Generate a unique project name if not provided
    project_name = data.get("project_name", f"wazuh-stack-{uuid.uuid4().hex[:8]}")

    # Set up environment variables
    env_vars = setup_environment_variables(port, password)

    # Run Docker Compose
    success, result = run_docker_compose(compose_file, env_vars, project_name)

    if success:
        logger.info(f"Successfully deployed {project_name}")
        return jsonify(result), 200
    else:
        logger.error(f"Failed to deploy {project_name}: {result['message']}")
        return jsonify(result), 500


# Rest of the endpoints remain the same
# ...

if __name__ == "__main__":
    # Get port from environment or use default
    api_port = int(os.environ.get("API_PORT", 6000))
    logger.info(f"Starting API server on port {api_port}")
    app.run(host="0.0.0.0", port=api_port, debug=False)
