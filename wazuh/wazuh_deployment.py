#!/usr/bin/env python3
"""
Wazuh Dynamic Deployment Script

This script provides a Flask-based web server that can:
1. Dynamically provision Wazuh instances using Docker
2. Create and manage Wazuh users programmatically
3. Provide API endpoints for instance and user management

Requirements:
- Python 3.8+
- Flask
- Docker SDK for Python
- Requests
- PyYAML
- python-dotenv

Environment variables (store in .env):
- WAZUH_ADMIN_PASSWORD: Default admin password for new instances
- DOCKER_HOST: Docker host to connect to (default: unix:///var/run/docker.sock)
- BASE_PORT: Starting port for Wazuh instances (default: 55000)
- DATA_DIR: Directory to store Wazuh persistent data (default: ./wazuh_data)
- DOCKER_WAZUH_IMAGE: Wazuh Docker image to use (default: wazuh/wazuh-manager:4.5.4)
"""

import os
import time
import uuid
import json
import yaml
import logging
import requests
import subprocess
import docker
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import base64
import hashlib
import threading
import shutil

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("wazuh_deployment.log"), logging.StreamHandler()],
)
logger = logging.getLogger("wazuh-deployment")

# Flask app
app = Flask(__name__)

# Constants and configuration
WAZUH_ADMIN_PASSWORD = os.getenv("WAZUH_ADMIN_PASSWORD", "SecurePassword123!")
DOCKER_HOST = os.getenv("DOCKER_HOST", "unix:///var/run/docker.sock")
BASE_PORT = int(os.getenv("BASE_PORT", "55000"))
DATA_DIR = os.getenv("DATA_DIR", "./wazuh_data")
WAZUH_DOCKER_IMAGE = os.getenv("DOCKER_WAZUH_IMAGE", "wazuh/wazuh-manager:4.5.4")
WAZUH_NETWORK_NAME = "wazuh-network"

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

# Database file for instance tracking
INSTANCES_DB = os.path.join(DATA_DIR, "instances.json")

# Initialize Docker client
docker_client = docker.from_env()

# Global variables
instances = {}


def load_instances():
    """Load existing instances from the database file."""
    global instances
    if os.path.exists(INSTANCES_DB):
        with open(INSTANCES_DB, "r") as f:
            instances = json.load(f)
        logger.info(f"Loaded {len(instances)} existing Wazuh instances")
    else:
        instances = {}
        save_instances()
        logger.info("Initialized empty instances database")


def save_instances():
    """Save instances to the database file."""
    with open(INSTANCES_DB, "w") as f:
        json.dump(instances, f, indent=2)
    logger.info(f"Saved {len(instances)} Wazuh instances to database")


def find_available_port() -> int:
    """Find an available port for a new Wazuh instance."""
    used_ports = set()
    for instance_id, instance_data in instances.items():
        used_ports.add(instance_data.get("api_port"))

    # Find the first available port starting from BASE_PORT
    port = BASE_PORT
    while port in used_ports:
        port += 1

    return port


def create_wazuh_instance(name: str, owner: str) -> Dict[str, Any]:
    """
    Create a new Wazuh instance with Docker.

    Args:
        name: Name for the Wazuh instance
        owner: Owner identifier

    Returns:
        Dict with instance details
    """
    try:
        instance_id = str(uuid.uuid4())
        api_port = find_available_port()
        instance_data_dir = os.path.join(DATA_DIR, instance_id)

        # Create required directories with proper permissions
        os.makedirs(instance_data_dir, exist_ok=True)
        os.makedirs(os.path.join(instance_data_dir, "etc"), exist_ok=True)
        os.makedirs(os.path.join(instance_data_dir, "logs"), exist_ok=True)
        os.makedirs(os.path.join(instance_data_dir, "var"), exist_ok=True)

        # Set proper permissions on the data directory
        os.chmod(instance_data_dir, 0o777)  # Full permissions for container

        # Ensure Wazuh network exists
        try:
            docker_client.networks.get(WAZUH_NETWORK_NAME)
        except docker.errors.NotFound:
            docker_client.networks.create(WAZUH_NETWORK_NAME, driver="bridge")
            logger.info(f"Created Wazuh network: {WAZUH_NETWORK_NAME}")

        # Create Wazuh container
        container = docker_client.containers.run(
            WAZUH_DOCKER_IMAGE,
            name=f"wazuh-{instance_id}",
            detach=True,
            ports={
                "1514/udp": None,  # Agents connection
                "1515/tcp": None,  # Agent registration service
                "55000/tcp": api_port,  # Wazuh API
            },
            environment={
                "WAZUH_API_USER": "wazuh-admin",
                "WAZUH_API_PASSWORD": WAZUH_ADMIN_PASSWORD,
            },
            volumes={instance_data_dir: {"bind": "/var/ossec", "mode": "rw"}},
            network=WAZUH_NETWORK_NAME,
            restart_policy={"Name": "unless-stopped"},
            privileged=True,  # Give necessary permissions
            ulimits=[docker.types.Ulimit(name="nofile", soft=65536, hard=65536)],
        )

        # Record instance details
        instance_data = {
            "id": instance_id,
            "name": name,
            "owner": owner,
            "created_at": datetime.now().isoformat(),
            "container_id": container.id,
            "api_port": api_port,
            "data_dir": instance_data_dir,
            "status": "starting",
            "users": [],  # Will be populated with users
        }

        instances[instance_id] = instance_data
        save_instances()

        # Start a thread to wait for instance to be ready
        threading.Thread(
            target=wait_for_wazuh_ready,
            args=(instance_id, container.id, api_port),
            daemon=True,
        ).start()

        logger.info(
            f"Created Wazuh instance: {instance_id} (Name: {name}, Owner: {owner})"
        )
        return instance_data

    except Exception as e:
        logger.error(f"Error creating Wazuh instance: {str(e)}")
        # Clean up if possible
        try:
            if "container" in locals() and container:
                container.remove(force=True)
            if "instance_data_dir" in locals() and os.path.exists(instance_data_dir):
                shutil.rmtree(instance_data_dir)
        except Exception as cleanup_error:
            logger.error(f"Error cleaning up failed instance: {str(cleanup_error)}")

        raise


def wait_for_wazuh_ready(instance_id: str, container_id: str, api_port: int):
    """
    Wait for the Wazuh instance to be ready and update its status.

    Args:
        instance_id: Wazuh instance ID
        container_id: Docker container ID
        api_port: Wazuh API port
    """
    max_attempts = 60  # Increase max attempts (each is 10 seconds)
    wait_seconds = 10

    for attempt in range(max_attempts):
        try:
            # Check if container is running
            container = docker_client.containers.get(container_id)
            if container.status != "running":
                logger.warning(
                    f"Container for instance {instance_id} is {container.status}, waiting..."
                )
                time.sleep(wait_seconds)
                continue

            # Check container logs for readiness
            logs = container.logs(tail=50).decode("utf-8")
            if "wazuh-modulesd: INFO: (wazuh-modulesd) Wazuh module started" in logs:
                logger.info(
                    f"Wazuh services detected as started in instance {instance_id}"
                )
                time.sleep(10)  # Give a little more time for API to be ready

            # Try to get authentication token from API
            token = get_wazuh_token(
                "localhost", api_port, "wazuh-admin", WAZUH_ADMIN_PASSWORD
            )
            if token:
                # Update instance status
                instances[instance_id]["status"] = "running"
                save_instances()

                # Create default users and roles
                create_default_users(instance_id)

                logger.info(f"Wazuh instance {instance_id} is now ready")
                return

        except Exception as e:
            logger.warning(
                f"Waiting for Wazuh instance {instance_id} to be ready. Attempt {attempt+1}/{max_attempts}: {str(e)}"
            )

        time.sleep(wait_seconds)

    # If we get here, instance didn't start properly
    logger.error(
        f"Wazuh instance {instance_id} failed to start after {max_attempts} attempts"
    )

    # Get container logs to diagnose issues
    try:
        container = docker_client.containers.get(container_id)
        logs = container.logs(tail=100).decode("utf-8")
        logger.error(f"Container logs for {instance_id}:\n{logs}")
    except Exception as log_error:
        logger.error(f"Error getting container logs: {str(log_error)}")

    instances[instance_id]["status"] = "error"
    save_instances()


def get_wazuh_token(
    host: str, port: int, username: str, password: str
) -> Optional[str]:
    """
    Get authentication token from Wazuh API.

    Args:
        host: Wazuh API host
        port: Wazuh API port
        username: Wazuh API username
        password: Wazuh API password

    Returns:
        Authentication token or None if failed
    """
    try:
        # Disable SSL verification for the API calls
        # In production, you should use proper certificates
        requests.packages.urllib3.disable_warnings()

        login_url = f"https://{host}:{port}/security/user/authenticate"
        basic_auth = base64.b64encode(f"{username}:{password}".encode()).decode()

        headers = {
            "Authorization": f"Basic {basic_auth}",
            "Content-Type": "application/json",
        }

        response = requests.get(
            login_url,
            headers=headers,
            verify=False,  # Disable SSL verification
        )

        if response.status_code == 200:
            return response.json()["data"]["token"]
        else:
            logger.error(f"Failed to get Wazuh token: {response.text}")
            return None

    except Exception as e:
        logger.error(f"Error getting Wazuh token: {str(e)}")
        return None


def wazuh_api_request(
    instance_id: str, endpoint: str, method: str = "GET", data: Optional[Dict] = None
) -> Tuple[int, Dict]:
    """
    Make a request to the Wazuh API.

    Args:
        instance_id: Wazuh instance ID
        endpoint: API endpoint (e.g., '/security/users')
        method: HTTP method (GET, POST, PUT, DELETE)
        data: Request data for POST/PUT methods

    Returns:
        Tuple of (status_code, response_data)
    """
    try:
        if instance_id not in instances:
            return 404, {"error": "Instance not found"}

        instance = instances[instance_id]
        if instance["status"] != "running":
            return 503, {"error": "Instance is not running"}

        # Get admin token
        token = get_wazuh_token(
            "localhost", instance["api_port"], "wazuh-admin", WAZUH_ADMIN_PASSWORD
        )

        if not token:
            return 500, {"error": "Could not authenticate with Wazuh API"}

        url = f"https://localhost:{instance['api_port']}{endpoint}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        # Make the request based on the method
        requests.packages.urllib3.disable_warnings()
        if method == "GET":
            response = requests.get(url, headers=headers, verify=False)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=data, verify=False)
        elif method == "PUT":
            response = requests.put(url, headers=headers, json=data, verify=False)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers, verify=False)
        else:
            return 400, {"error": f"Unsupported method: {method}"}

        return response.status_code, response.json()

    except Exception as e:
        logger.error(f"Error making Wazuh API request: {str(e)}")
        return 500, {"error": str(e)}


def create_default_users(instance_id: str):
    """
    Create default users and roles for a Wazuh instance.

    Args:
        instance_id: Wazuh instance ID
    """
    try:
        # Create a default analyst role
        role_data = {
            "name": "analyst",
            "policy": {
                "actions": [
                    "agent:read",
                    "group:read",
                    "vulnerability:read",
                    "rules:read",
                    "decoders:read",
                ],
                "resources": ["agent:id:*", "group:id:*", "*:*:*"],
                "effect": "allow",
            },
        }

        status, response = wazuh_api_request(
            instance_id, "/security/roles", method="POST", data=role_data
        )

        if status != 200:
            logger.warning(f"Failed to create default analyst role: {response}")
        else:
            logger.info(f"Created default analyst role for instance {instance_id}")

        # Add default admin user to the instance record
        instances[instance_id]["users"].append(
            {
                "username": "wazuh-admin",
                "role": "administrator",
                "created_at": datetime.now().isoformat(),
            }
        )
        save_instances()

    except Exception as e:
        logger.error(
            f"Error creating default users for instance {instance_id}: {str(e)}"
        )


def create_user(
    instance_id: str, username: str, password: str, role: str
) -> Tuple[int, Dict]:
    """
    Create a new user in a Wazuh instance.

    Args:
        instance_id: Wazuh instance ID
        username: Username for the new user
        password: Password for the new user
        role: Role for the new user (e.g., 'administrator', 'analyst')

    Returns:
        Tuple of (status_code, response_data)
    """
    try:
        # Check if instance exists
        if instance_id not in instances:
            return 404, {"error": "Instance not found"}

        # Create user via API
        user_data = {"username": username, "password": password}

        status, response = wazuh_api_request(
            instance_id, "/security/users", method="POST", data=user_data
        )

        if status != 200:
            return status, response

        # Get the user ID
        user_id = response["data"]["affected_items"][0]["id"]

        # Get the role ID
        status, roles_response = wazuh_api_request(
            instance_id, "/security/roles", method="GET"
        )

        if status != 200:
            return status, roles_response

        role_id = None
        for r in roles_response["data"]["affected_items"]:
            if r["name"] == role:
                role_id = r["id"]
                break

        if not role_id:
            return 400, {"error": f"Role '{role}' not found"}

        # Assign the role to the user
        status, role_assignment = wazuh_api_request(
            instance_id,
            f"/security/users/{user_id}/roles",
            method="POST",
            data={"role_ids": [role_id]},
        )

        if status != 200:
            return status, role_assignment

        # Add user to the instance record
        instances[instance_id]["users"].append(
            {
                "username": username,
                "role": role,
                "created_at": datetime.now().isoformat(),
            }
        )
        save_instances()

        return 200, {"message": f"User {username} created successfully"}

    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        return 500, {"error": str(e)}


def delete_instance(instance_id: str) -> Dict[str, Any]:
    """
    Delete a Wazuh instance and clean up resources.

    Args:
        instance_id: Wazuh instance ID

    Returns:
        Dict with operation result
    """
    try:
        if instance_id not in instances:
            return {"error": "Instance not found"}

        instance = instances[instance_id]

        # Stop and remove the container
        try:
            container = docker_client.containers.get(instance["container_id"])
            container.stop()
            container.remove()
            logger.info(f"Removed Docker container for instance {instance_id}")
        except docker.errors.NotFound:
            logger.warning(f"Container for instance {instance_id} already removed")
        except Exception as e:
            logger.error(f"Error removing container: {str(e)}")

        # Remove data directory
        try:
            shutil.rmtree(instance["data_dir"])
            logger.info(f"Removed data directory for instance {instance_id}")
        except Exception as e:
            logger.error(f"Error removing data directory: {str(e)}")

        # Remove from instances dictionary
        del instances[instance_id]
        save_instances()

        return {"message": f"Instance {instance_id} deleted successfully"}

    except Exception as e:
        logger.error(f"Error deleting instance: {str(e)}")
        return {"error": str(e)}


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "ok", "instances_count": len(instances)})


@app.route("/instances", methods=["GET"])
def list_instances():
    """List all Wazuh instances."""
    return jsonify(instances)


@app.route("/instances", methods=["POST"])
def create_instance():
    """Create a new Wazuh instance."""
    try:
        data = request.json

        # Validate request
        if not data or "name" not in data or "owner" not in data:
            return jsonify({"error": "Missing required fields: name, owner"}), 400

        instance = create_wazuh_instance(data["name"], data["owner"])
        return jsonify(instance), 201

    except Exception as e:
        logger.error(f"Error creating instance: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/instances/<instance_id>", methods=["GET"])
def get_instance(instance_id):
    """Get details for a specific Wazuh instance."""
    if instance_id not in instances:
        return jsonify({"error": "Instance not found"}), 404

    return jsonify(instances[instance_id])


@app.route("/instances/<instance_id>", methods=["DELETE"])
def remove_instance(instance_id):
    """Delete a Wazuh instance."""
    result = delete_instance(instance_id)

    if "error" in result:
        return jsonify(result), 400

    return jsonify(result)


@app.route("/instances/<instance_id>/users", methods=["POST"])
def add_user(instance_id):
    """Add a user to a Wazuh instance."""
    try:
        data = request.json

        # Validate request
        if not data or "username" not in data or "password" not in data:
            return jsonify(
                {"error": "Missing required fields: username, password"}
            ), 400

        role = data.get("role", "analyst")  # Default to 'analyst' if not specified

        status, response = create_user(
            instance_id, data["username"], data["password"], role
        )

        return jsonify(response), status

    except Exception as e:
        logger.error(f"Error adding user: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/instances/<instance_id>/users", methods=["GET"])
def list_users(instance_id):
    """List all users for a Wazuh instance."""
    if instance_id not in instances:
        return jsonify({"error": "Instance not found"}), 404

    return jsonify({"users": instances[instance_id]["users"]})


@app.route("/instances/<instance_id>/status", methods=["GET"])
def instance_status(instance_id):
    """Get the current status of a Wazuh instance."""
    if instance_id not in instances:
        return jsonify({"error": "Instance not found"}), 404

    try:
        # Get container status
        container_id = instances[instance_id]["container_id"]
        try:
            container = docker_client.containers.get(container_id)
            container_status = container.status
        except:
            container_status = "unknown"

        # Update instance status if needed
        current_status = instances[instance_id]["status"]
        if container_status != "running" and current_status == "running":
            instances[instance_id]["status"] = "stopped"
            save_instances()

        # Return detailed status
        return jsonify(
            {
                "instance_id": instance_id,
                "status": instances[instance_id]["status"],
                "container_status": container_status,
                "api_port": instances[instance_id]["api_port"],
                "name": instances[instance_id]["name"],
                "owner": instances[instance_id]["owner"],
            }
        )

    except Exception as e:
        logger.error(f"Error getting instance status: {str(e)}")
        return jsonify({"error": str(e)}), 500


# Main entry point
if __name__ == "__main__":
    try:
        # Load existing instances
        load_instances()

        # Check Docker connection
        docker_client.ping()
        logger.info("Connected to Docker successfully")

        # Start the API server
        app.run(host="0.0.0.0", port=8080, debug=False)

    except Exception as e:
        logger.error(f"Failed to start Wazuh Deployment Service: {str(e)}")

