FROM python:3.11-slim

RUN apt-get update && apt-get install -y libpcap-dev && rm -rf /var/lib/apt/lists/*
RUN pip install scapy pyyaml flask

WORKDIR /app
COPY cnf_api.py .
COPY arp_proxy/arp_proxy.py .
COPY arp_proxy/arp_proxy.yaml .

EXPOSE 8081

CMD ["python3", "arp_proxy.py"]
