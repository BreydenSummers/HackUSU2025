FROM python:3.10-slim

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
  curl \
  gnupg \
  lsb-release \
  build-essential \
  python3-dev \
  libyaml-dev \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Install Docker CLI (needed for creating Wazuh containers)
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
RUN echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian \
  $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
RUN apt-get update && apt-get install -y docker-ce-cli

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY wazuh_deployment.py .

# Create data directory
RUN mkdir -p /app/wazuh_data

# Set permissions
RUN chmod +x /app/wazuh_deployment.py

# Expose API port
EXPOSE 8080

# Command to run the application
CMD ["python", "wazuh_deployment.py"]
