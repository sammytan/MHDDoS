import requests

proxyip = "http://lumi-quinntan:MNQicSrsGy8RYyP@as.lumiproxy.com:5888"
url = "https://api.ip.cc/en"
proxies={
    'http':proxyip,
    'https':proxyip,
}
data = requests.get(url=url,proxies=proxies)
print(data)
print(data.text)
