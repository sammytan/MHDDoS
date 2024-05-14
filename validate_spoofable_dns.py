# -*- coding: utf-8 -*-

import dns.message
import dns.query
import socket
import random
import requests

# ��Դ����
urls = [
    "https://public-dns.info/nameservers.txt",
    "https://github.com/opendnssec/parent/blob/develop/doc/examples/example.txt"
]

valid_servers = []

# ��ȡ���� DNS �б�
def fetch_public_dns(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text.splitlines()
    except Exception as e:
        print(f"Failed to fetch DNS list from {url}: {e}")
    return []

# ����һ�� DNS ��ѯ����
query = dns.message.make_query('example.com', dns.rdatatype.A)

def check_spoofable(server):
    try:
        # ���ʹ�α��Դ IP �� DNS ��ѯ
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        # α��Դ IP ��ַ
        fake_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        sock.bind((fake_ip, 0))
        sock.sendto(query.to_wire(), (server, 53))
        response = sock.recv(512)
        if response:
            return True
    except (socket.timeout, socket.error, dns.exception.DNSException):
        return False
    finally:
        sock.close()

def process_servers(servers):
    for server in servers:
        if check_spoofable(server):
            valid_servers.append(server)
            print(f"Valid and spoofable DNS server: {server}")

# �Ӷ����Դ��ȡ DNS �б�
for url in urls:
    servers = fetch_public_dns(url)
    process_servers(servers)

# ������Ч�� DNS �������� reflectors.txt �ļ�
with open('reflectors.txt', 'w') as f:
    for server in valid_servers:
        f.write(f"{server}\n")

print(f"Total valid and spoofable DNS servers: {len(valid_servers)}")
