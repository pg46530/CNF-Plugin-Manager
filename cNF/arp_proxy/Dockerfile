FROM python:3.11-slim

RUN apt-get update && apt-get install -y libpcap-dev && rm -rf /var/lib/apt/lists/*
RUN pip install scapy pyyaml

WORKDIR /app
COPY arp_proxy.py .
COPY arp_proxy.yaml .

CMD ["python3", "arp_proxy.py"]
