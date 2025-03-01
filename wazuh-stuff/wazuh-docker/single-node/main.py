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

        # Update internal_users.yml with the hashed password
        compose_dir = os.path.dirname(os.path.abspath(compose_file))
        if not update_internal_users_file(compose_dir, env_vars["PASSWORD"]):
            logger.warning(
                "Could not update internal_users.yml, login may not work correctly"
            )

        # Pull images first to ensure we have the latest
        logger.info("Pulling Docker images...")
        pull_cmd = ["docker-compose", "-f", compose_file, "-p", project_name, "pull"]
        subprocess.run(pull_cmd, env=env_vars, check=True)

        # Start the services
        logger.info(f"Starting services for project {project_name}...")
        cmd = ["docker-compose", "-f", compose_file, "-p", project_name, "up", "-d"]
        subprocess.run(cmd, env=env_vars, check=True)

        # Wait for services to initialize
        logger.info("Waiting for services to initialize...")
        time.sleep(int(env_vars.get("STARTUP_WAIT_TIME", 60)))

        # Get container status to verify
        status_cmd = ["docker-compose", "-f", compose_file, "-p", project_name, "ps"]
        status_result = subprocess.run(
            status_cmd, env=env_vars, check=True, capture_output=True, text=True
        )

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
    api_port = int(os.environ.get("API_PORT", 5000))
    logger.info(f"Starting API server on port {api_port}")
    app.run(host="0.0.0.0", port=api_port, debug=False)
