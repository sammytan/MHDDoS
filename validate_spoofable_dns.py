# -*- coding: utf-8 -*-

import dns.message
import dns.query
import socket
import random
import requests
import concurrent.futures
import argparse
import os

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

def check_spoofable(server, checked_count):
    try:
        print(f"Checking DNS server: {server} (Checked {checked_count})")
        # ���ʹ�α��Դ IP �� DNS ��ѯ
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        # α��Դ IP ��ַ
        fake_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        sock.bind((fake_ip, 0))
        sock.sendto(query.to_wire(), (server, 53))
        response = sock.recv(512)
        if response:
            print(f"Valid and spoofable DNS server: {server}")
            return server
    except (socket.timeout, socket.error, dns.exception.DNSException) as e:
        print(f"Failed to check DNS server: {server} ({e})")
    finally:
        sock.close()
    return None

def process_servers(servers, threads):
    checked_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for server in servers:
            checked_count += 1
            futures.append(executor.submit(check_spoofable, server, checked_count))
        
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
    return [server for server in results if server is not None]

# ���������в���
parser = argparse.ArgumentParser(description="Validate DNS servers for spoofing.")
parser.add_argument('-t', '--threads', type=int, default=os.cpu_count(), help="Number of threads to use.")
args = parser.parse_args()

# �Ӷ����Դ��ȡ DNS �б�
all_servers = []
for url in urls:
    servers = fetch_public_dns(url)
    all_servers.extend(servers)
    print(f"Fetched {len(servers)} DNS servers from {url}")

print(f"Total DNS servers to check: {len(all_servers)}")

# ������֤ DNS ������
valid_servers = process_servers(all_servers, args.threads)

# ������Ч�� DNS �������� reflectors.txt �ļ�
with open('reflectors.txt', 'w') as f:
    for server in valid_servers:
        f.write(f"{server}\n")

print(f"Total valid and spoofable DNS servers: {len(valid_servers)}")
