import socket
import threading
import argparse
import json
import time
from termcolor import cprint
from pyfiglet import figlet_format

#                '''<    -------------Style-color-Function------------  >'''
class Style:
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    RESET = '\033[0m'
    MAGENTA = '\033[35m'
    VIOLET = '\033[36m'
    BOLD = '\033[1m'
#                 '''<    ----------Display--Banner--Funtion---------   >'''
def display_banner():
    cprint(figlet_format('ZETA-scan', font='standard'), 'red', attrs=['bold'])
    print(f"{Style.GREEN}{Style.BOLD}BY - UZAIR AMJAD {Style.RESET}\n")


#                   '''<    --------------Port-Scanning-Fucntion---------   >'''

def scan_port(host, port, database, report, lock):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                banner = get_banner(sock)
                lock.acquire()
                report.append(f"[OPEN] Port {port}: {banner}")
                print(f"{Style.GREEN}[OPEN]{Style.RESET} {port}/tcp    {Style.BLUE}{banner}{Style.RESET}")
                lock.release()
                check_vulnerability(port, banner, database, report, lock)
    except Exception as e:
        pass  

#                   '''<    --------------Banner-of-service-Fucntion---------   >'''


def get_banner(sock):
    try:
        return sock.recv(1024).decode().strip()
    except Exception:
        return "No banner"

#                   '''<    --------------Vulenrabilitu-Check-Fucntion---------   >'''

def check_vulnerability(port, banner, database, report, lock):
    for probe in database.get("probes", []):
        for match in probe.get("matches", []):
            if match.get("pattern") in banner:
                lock.acquire()
                report.append(f"[VULNERABLE] Port {port}: {match.get('service')} identified")
                print(f"{Style.RED}[VULNERABLE]{Style.RESET} Port {port}: {Style.YELLOW}{match.get('service')} detected!{Style.RESET}")
                lock.release()

#                    '''<    --------------For---Threads-Fucntion----------    >'''

def worker(host, port_range, database, report, lock):
    for port in port_range:
        scan_port(host, port, database, report, lock)

#                    '''<    ------------------Main--Fucntion---------------    >'''                 

def main():
    display_banner()
    parser = argparse.ArgumentParser(description="Port and Vulnerability Scanner with Nmap-Style Verbose Mode")
    parser.add_argument("-host", required=True, help="Target IP or URL")
    parser.add_argument("-t", type=int, default=100, help="Max threads (default: 100)")
    parser.add_argument("-s", type=int, required=True, help="Starting port")
    parser.add_argument("-e", type=int, required=True, help="Ending port")
    args = parser.parse_args()

    host = args.host
    start_port = args.s
    end_port = args.e
    max_threads = args.t

#                    '''<    --------------Load--Database--Fucntion----------    >'''

    print(f"{Style.YELLOW}ZETA scan initiated on host: {host}{Style.RESET}")
    print("[INFO] Loading vulnerabilities database...")
    with open("nmap_service_probes.json", "r") as file:
        database = json.load(file)

    print(f"{Style.GREEN}[INFO] Database loaded successfully.{Style.RESET}")
    report = []
    threads = []
    lock = threading.Lock()
    port_range = range(start_port, end_port + 1)
    chunk_size = len(port_range) // max_threads

#                    '''<    --------------Create---Threads-Fucntion----------    >'''
    
    print(f"{Style.YELLOW}[INFO] Starting scan from port {start_port} to {end_port}...{Style.RESET}")
    start_time = time.time()
    for i in range(max_threads):
        ports_to_scan = list(port_range[i * chunk_size:(i + 1) * chunk_size])
        if ports_to_scan:
            thread = threading.Thread(target=worker, args=(host, ports_to_scan, database, report, lock))
            threads.append(thread)
            thread.start()

#                    '''<    --------------Wait-For-Threads-Fucntion----------    >'''

    for thread in threads:
        thread.join()

#                    '''<    --------------Wait-For-Gen-Rep--Fucntion----------    >'''

    print(f"{Style.BLUE}[INFO] Scan complete. Generating report...{Style.RESET}")
    with open("scan_report.txt", "w") as file:
        file.write("\n".join(report))

    end_time = time.time()
    print(f"{Style.GREEN}Scan completed in {end_time - start_time:.2f} seconds.{Style.RESET}")
    print(f"{Style.VIOLET}Report saved to 'scan_report.txt'.{Style.RESET}")

if __name__ == "__main__":
    main()
 
 
 #                    '''<    --------------COMPLETED--------------    >'''
 
 #@UZAIR-AMJAD
 # 2023-02-15
 #https://github.com/Uzair-Baig0900