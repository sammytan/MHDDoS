# -*- coding: utf-8 -*-

import dns.message
import dns.query
import socket
import random
import concurrent.futures
import os
import argparse

# ���������в���
parser = argparse.ArgumentParser(description="Validate DNS servers for spoofing.")
parser.add_argument('input_file', type=str, help="Input file with DNS servers (one per line).")
parser.add_argument('output_file', type=str, help="Output file for valid spoofable DNS servers.")
parser.add_argument('-t', '--threads', type=int, default=os.cpu_count(), help="Number of threads to use.")
args = parser.parse_args()

# �������ļ�
with open(args.input_file, 'r') as f:
    dns_servers = [line.strip() for line in f]

valid_servers = []

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

def process_server(server):
    if check_spoofable(server):
        print(f"Valid and spoofable DNS server: {server}")
        return server
    return None

# ʹ�� ThreadPoolExecutor ��������
with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
    results = list(executor.map(process_server, dns_servers))

# ������Ч�ķ�����
valid_servers = [server for server in results if server is not None]

# ������Ч�� DNS ������������ļ�
with open(args.output_file, 'w') as f:
    for server in valid_servers:
        f.write(f"{server}\n")

print(f"Total valid and spoofable DNS servers: {len(valid_servers)}")
