FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    sqlite3 \
    make \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install static Docker CLI and Docker Compose binaries for socket passthrough
RUN curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-26.1.4.tgz | tar -xz -C /tmp && \
    mv /tmp/docker/docker /usr/local/bin/ && \
    rm -rf /tmp/docker && \
    mkdir -p /usr/libexec/docker/cli-plugins && \
    curl -fsSL https://github.com/docker/compose/releases/download/v2.29.2/docker-compose-linux-x86_64 -o /usr/libexec/docker/cli-plugins/docker-compose && \
    chmod +x /usr/libexec/docker/cli-plugins/docker-compose && \
    ln -s /usr/libexec/docker/cli-plugins/docker-compose /usr/local/bin/docker-compose

WORKDIR /workspace

# Copy dependency files first for Docker cache optimization
COPY pyproject.toml requirements.txt ./

# Copy source code and installation files
COPY . .

# Install dependencies and local package in editable mode
RUN pip install --no-cache-dir --default-timeout=100 -e .

EXPOSE 8501

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/workspace
ENV STREAMLIT_SERVER_PORT=8501
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0
ENV STREAMLIT_SERVER_HEADLESS=true

CMD ["streamlit", "run", "frontend/app.py"]
