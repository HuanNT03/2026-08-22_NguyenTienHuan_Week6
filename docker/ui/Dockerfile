FROM python:3.11-slim

# Install system dependencies including docker-cli for scanner execution
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    docker.io \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Copy dependency files first for Docker cache optimization
COPY pyproject.toml requirements.txt ./

# Copy source code and installation files
COPY . .

# Install dependencies and local package in editable mode
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e .

EXPOSE 8501

ENV PYTHONUNBUFFERED=1
ENV STREAMLIT_SERVER_PORT=8501
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0
ENV STREAMLIT_SERVER_HEADLESS=true

CMD ["streamlit", "run", "frontend/app.py"]
