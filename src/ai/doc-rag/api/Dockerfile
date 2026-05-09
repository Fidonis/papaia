FROM python:3.12-slim

WORKDIR /app

COPY api/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ shared/
COPY api/main.py main.py

CMD ["python", "-u", "main.py"]
