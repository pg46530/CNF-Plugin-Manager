FROM python:3.11-slim

RUN apt-get update && apt-get install -y libpcap-dev && rm -rf /var/lib/apt/lists/*
RUN pip install scapy pyyaml

WORKDIR /app
COPY dhcp_server.py .
COPY dhcp_server.yaml .

CMD ["python3", "dhcp_server.py"]
