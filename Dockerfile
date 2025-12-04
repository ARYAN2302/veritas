# =============================================================================
# VERITAS - Automated Red Teaming Suite for AI Agents
# Docker image for running scans in isolation
# =============================================================================

FROM python:3.11-slim

# Labels
LABEL maintainer="Adarsh Thakur"
LABEL description="Veritas - Automated Red Teaming Suite for AI Agents"
LABEL version="1.0.0"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md LICENSE* ./
COPY src/ ./src/
COPY veritas.py ./
COPY examples/ ./examples/

# Install Python dependencies
RUN pip install --no-cache-dir -e ".[full]"

# Create directories for reports and models
RUN mkdir -p /app/reports /app/models /app/data

# Copy trained model if exists (optional)
COPY models/ ./models/ 2>/dev/null || true

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Default command
ENTRYPOINT ["python", "-m", "veritas"]
CMD ["--help"]

# =============================================================================
# Usage:
#   docker build -t veritas .
#   docker run veritas scan --help
#   docker run -e GROQ_API_KEY=xxx veritas scan
#   docker run -v $(pwd)/reports:/app/reports veritas scan -o /app/reports/scan.pdf
# =============================================================================
