FROM python:3.13-slim

# Create a non-root user for security
RUN useradd --no-create-home --shell /bin/false cleanup

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY cleanup.py .

# Switch to non-root user
USER cleanup

CMD ["python", "-u", "cleanup.py"]
