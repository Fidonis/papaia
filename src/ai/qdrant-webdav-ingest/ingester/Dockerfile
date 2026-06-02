FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        poppler-utils \
    && rm -rf /var/lib/apt/lists/*

COPY ingester/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY ingester/main.py main.py

CMD ["python", "-u", "main.py"]
