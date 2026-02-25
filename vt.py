# --- Imports ---

import ipaddress
import requests
import os
import time
from dotenv import load_dotenv

from tabulate import tabulate

# --- Variables ---

load_dotenv()

ioc_file = "example.txt"

api_base_url = "https://www.virustotal.com/api/v3/ip_addresses/"

api_key = os.getenv("VT_API_KEY")
headers = {
    "accept": "application/json",
    "x-apikey": api_key           
}

# --- Functions ---

def read_file(ioc_file):
    try:
        content = []
        with open(ioc_file, 'r') as f:
            for line in f:
                line = line.removesuffix("\n")
                try:
                    ipaddress.IPv4Address(line)
                    content.append(line)
                except:
                    print(f"{line} is not a valid IP address. Skipping.")
        return content

    except FileNotFoundError:
        print(f"File {ioc_file} not found.")
    except IOError:
        print(f"Cannot read {ioc_file}")

def filter_global_ipv4(ip_strs):
    # Remove loopback, multicast, rfc 1918 and duplicates

    filtered_ips = []

    for ip_str in ip_strs:
        ip_obj = ipaddress.IPv4Address(ip_str)
        if ip_str not in filtered_ips and ip_obj.is_global:
            filtered_ips.append(ip_str)
    
    filtered_ips.sort()
    return(filtered_ips)

def vt_api_call(url, headers, filtered_ips):
    vt_results = {}
    for ip in filtered_ips:
        print(f"query {ip}")
        vt_results[ip] = None
        # Public API is limited to 4 requests per minute
        url = api_base_url + ip
        try: 
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()

            vt_results[ip] = response.json()
    
        except requests.exceptions.Timeout as e:
            print(f"Connection timeout: {e}")
        except requests.exceptions.HTTPError as e:
            print(f"HTTP error: {e}")
        except requests.exceptions.ConnectionError as e:
            print(f"Connection error: {e}")
        finally:
            time.sleep(15)
    return vt_results

def format_results(vt_results):
    results_summarized = {}
    for ip, inner_dict in vt_results.items():
        counts = {
            "harmless": 0,
            "malicious": 0,
            "suspicious": 0,
            "timeout": 0,
            "undetected": 0
        }

        scan_results = inner_dict['data']['attributes']['last_analysis_results']
        for result in scan_results.values():
            cat = result["category"]
            if cat in counts:
                counts[cat] += 1

        results_summarized[ip] = counts

    return(results_summarized)

def print_summary(results_summarized):
    headers = ["IP address", "harmless", "malicious", "suspicous", "timeout", "undetected"]
    rows = []
    for ip, result in results_summarized.items():
        categories = ["harmless", "malicious", "suspicious", "timeout", "undetected"]
        values = [result.get(cat, 0)for cat in categories]  
        rows.append([ip, *values])

    create_table(headers, rows)
    
def create_table(headers, rows):
    print(tabulate(rows, headers=headers, tablefmt="fancy_grid", numalign="center"))

def main():
    ip_strs = read_file(ioc_file)

    filtered_ips = filter_global_ipv4(ip_strs)

    vt_results = vt_api_call(api_base_url, headers, filtered_ips)

    results_summarized = format_results(vt_results)

    print_summary(results_summarized)

if __name__ == "__main__":
    main()