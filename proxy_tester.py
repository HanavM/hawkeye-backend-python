import json
import requests
from concurrent.futures import ThreadPoolExecutor

def fetch_proxies():
    url = "https://api.proxyscrape.com/v4/free-proxy-list/get?request=get_proxies&proxy_format=protocolipport&format=json"
    try:
        proxies = requests.get(url, timeout=10).json()
        with open('proxies.json', 'w') as f:
            json.dump(proxies, f, indent=4)
        print("Proxies fetched and saved.")
        return proxies.get("proxies", [])
    except requests.exceptions.RequestException as e:
        print(f"Error fetching proxies: {e}")
        return []

def test_proxy(proxy):
    proxy_url = f"{proxy['protocol']}://{proxy['ip']}:{proxy['port']}"
    try:
        response = requests.get("http://httpbin.org/ip", proxies={'http': proxy_url, 'https': proxy_url}, timeout=5)
        if response.status_code == 200:
            print(f"Working Proxy: {proxy_url}")
            return proxy_url
    except requests.exceptions.RequestException:
        pass
    return None

def test_all_proxies(proxies):
    with ThreadPoolExecutor(max_workers=250) as executor:
        working_proxies = list(filter(None, executor.map(test_proxy, proxies)))

    print("\nAll Working Proxies:")
    for proxy in working_proxies:
        print(proxy)
proxies = fetch_proxies()
if proxies:
    test_all_proxies(proxies)