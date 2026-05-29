FROM python:3.11-slim

RUN apt-get update && apt-get install -y libpcap-dev && rm -rf /var/lib/apt/lists/*
RUN pip install scapy pyyaml flask

WORKDIR /app
COPY cnf_api.py .
COPY dhcp_server/dhcp_server.py .
COPY dhcp_server/dhcp_server.yaml .

EXPOSE 8080

CMD ["python3", "dhcp_server.py"]
