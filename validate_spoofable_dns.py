# -*- coding: utf-8 -*-

import dns.message
import dns.query
import socket
import random
import requests

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

def check_spoofable(server):
    try:
        # 发送带伪造源 IP 的 DNS 查询
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        # 伪造源 IP 地址
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

# 从多个资源获取 DNS 列表
for url in urls:
    servers = fetch_public_dns(url)
    process_servers(servers)

# 保存有效的 DNS 服务器到 reflectors.txt 文件
with open('reflectors.txt', 'w') as f:
    for server in valid_servers:
        f.write(f"{server}\n")

print(f"Total valid and spoofable DNS servers: {len(valid_servers)}")
