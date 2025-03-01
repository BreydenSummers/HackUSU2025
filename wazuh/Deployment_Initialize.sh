#!/bin/bash
# Wazuh Dynamic Deployment - Initialization Script
# This script sets up the Wazuh deployment service environment

set -e

echo "===== Wazuh Dynamic Deployment Service Setup ====="
echo "Setting up the environment..."

# Create necessary directories
mkdir -p wazuh_data
chmod 777 wazuh_data

# Check if Docker is installed
if ! command -v docker &>/dev/null; then
  echo "Docker is not installed. Installing Docker..."
  curl -fsSL https://get.docker.com -o get-docker.sh
  sudo sh get-docker.sh
  sudo usermod -aG docker $USER
  rm get-docker.sh
  echo "Docker installed successfully."
else
  echo "Docker is already installed."
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &>/dev/null; then
  echo "Docker Compose is not installed. Installing Docker Compose..."
  sudo curl -L "https://github.com/docker/compose/releases/download/v2.18.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
  sudo chmod +x /usr/local/bin/docker-compose
  echo "Docker Compose installed successfully."
else
  echo "Docker Compose is already installed."
fi

# Copy files to their correct locations if they don't exist
# if [ ! -f "wazuh_deployment.py" ]; then
#     echo "Copying main script..."
#     # Replace with your actual source file location
#     cp /path/to/source/wazuh_deployment.py .
# fi

if [ ! -f "requirements.txt" ]; then
  echo "Creating requirements.txt..."
  cat >requirements.txt <<EOF
Flask==2.2.3
docker==6.1.1
requests==2.28.2
PyYAML==6.0
python-dotenv==1.0.0
EOF
fi

# if [ ! -f "Dockerfile" ]; then
#     echo "Creating Dockerfile..."
#     # Content from the Dockerfile artifact would be here
#     cp /path/to/source/Dockerfile .
# fi
#
# if [ ! -f "docker-compose.yml" ]; then
#     echo "Creating docker-compose.yml..."
#     # Content from the docker-compose artifact would be here
#     cp /path/to/source/docker-compose.yml .
# fi

# Create .env file for configuration
if [ ! -f ".env" ]; then
  echo "Creating .env configuration file..."
  cat >.env <<EOF
# Wazuh Deployment Configuration
WAZUH_ADMIN_PASSWORD=AdminPa$$w0rd2025
BASE_PORT=55000
DATA_DIR=./wazuh_data
EOF
  echo "Created .env file with default values. Please update with secure passwords."
fi

echo ""
echo "Environment setup complete!"
echo ""
echo "To start the Wazuh Deployment Service, run:"
echo "docker-compose up -d"
echo ""
echo "To check the status, run:"
echo "docker-compose ps"
echo ""
echo "To view logs, run:"
echo "docker-compose logs -f"
echo ""
echo "The API will be available at: http://localhost:8080"
echo "=============================================="
