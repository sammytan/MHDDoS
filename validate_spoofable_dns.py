# -*- coding: utf-8 -*-

import dns.message
import dns.query
import socket
import random
import requests
import concurrent.futures
import argparse
import os

# 资源链接
urls = [
    "https://public-dns.info/nameservers.txt",
    "https://github.com/opendnssec/parent/blob/develop/doc/examples/example.txt"
]

valid_servers = []

# 获取公共 DNS 列表
def fetch_public_dns(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text.splitlines()
    except Exception as e:
        print(f"Failed to fetch DNS list from {url}: {e}")
    return []

# 生成一个 DNS 查询请求
query = dns.message.make_query('example.com', dns.rdatatype.A)

def check_spoofable(server, checked_count):
    try:
        print(f"Checking DNS server: {server} (Checked {checked_count})")
        # 发送带伪造源 IP 的 DNS 查询
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        # 伪造源 IP 地址
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

# 解析命令行参数
parser = argparse.ArgumentParser(description="Validate DNS servers for spoofing.")
parser.add_argument('-t', '--threads', type=int, default=os.cpu_count(), help="Number of threads to use.")
args = parser.parse_args()

# 从多个资源获取 DNS 列表
all_servers = []
for url in urls:
    servers = fetch_public_dns(url)
    all_servers.extend(servers)
    print(f"Fetched {len(servers)} DNS servers from {url}")

print(f"Total DNS servers to check: {len(all_servers)}")

# 处理并验证 DNS 服务器
valid_servers = process_servers(all_servers, args.threads)

# 保存有效的 DNS 服务器到 reflectors.txt 文件
with open('reflectors.txt', 'w') as f:
    for server in valid_servers:
        f.write(f"{server}\n")

print(f"Total valid and spoofable DNS servers: {len(valid_servers)}")
