FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        poppler-utils \
        libgl1 \
        libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Install PyTorch with CUDA support before docling so it pulls in the GPU build.
# cu128 targets CUDA 12.8, compatible with driver 590+ (CUDA 13.1 max).
RUN pip install --no-cache-dir torch==2.7.1 torchvision==0.22.1 --index-url https://download.pytorch.org/whl/cu128

COPY ingester/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ shared/
COPY ingester/main.py main.py

CMD ["python", "-u", "main.py"]
