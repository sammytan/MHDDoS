# -*- coding: utf-8 -*-
import dns.message
import dns.query
import socket
import random
import concurrent.futures
import os
import argparse

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
    valid_servers = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for server in servers:
            checked_count += 1
            futures.append(executor.submit(check_spoofable, server, checked_count))
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                valid_servers.append(result)
            print(f"Checked {checked_count} servers, {len(valid_servers)} valid")

    return valid_servers

# ���������в���
parser = argparse.ArgumentParser(description="Validate DNS servers for spoofing.")
parser.add_argument('-i', '--input', type=str, default='dns.txt', help="Input file with DNS servers.")
parser.add_argument('-o', '--output', type=str, default='reflectors.txt', help="Output file for valid DNS servers.")
parser.add_argument('-t', '--threads', type=int, default=os.cpu_count(), help="Number of threads to use.")
args = parser.parse_args()

# �������ļ���ȡ DNS �������б�
with open(args.input, 'r') as f:
    all_servers = [line.strip().split()[0] for line in f]

print(f"Total DNS servers to check: {len(all_servers)}")

# ������֤ DNS ������
valid_servers = process_servers(all_servers, args.threads)

# ������Ч�� DNS ������������ļ�
with open(args.output, 'w') as f:
    for server in valid_servers:
        f.write(f"{server}\n")

print(f"Total valid and spoofable DNS servers: {len(valid_servers)}")