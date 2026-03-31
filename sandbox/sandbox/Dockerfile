# Use minimal Python image
FROM python:3.11-slim

# Install procps to provide 'ps', 'free', 'uptime', etc. for the sandbox environment
RUN apt-get update && apt-get install -y procps iproute2 net-tools && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m -s /bin/bash sandboxuser

# Set working directory
WORKDIR /app

# Copy the application code
COPY --chown=sandboxuser:sandboxuser . /app

# Switch to non-root user
USER sandboxuser

# Default command
CMD ["python", "main.py"]
