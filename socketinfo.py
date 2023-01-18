import socket
import requests
import re
import threading
import subprocess
import pydig
import sys
from tabulate import tabulate

regex_ip = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
get_arg = sys.argv[1]

if len(sys.argv) > 2:
    print('Too much arguments, only IP address or FQDN name')
    sys.exit()

def ping_addr(address):
    try:
        ping_result = subprocess.run(f'ping -c 3 {address}', shell=True, capture_output=True).returncode
        if ping_result == 0:
            print(tabulate([('Address is responding to ping',)]))
        else:
            print(tabulate([('Address is not responding to ping',)]))
    except Exception as e:
        print(e)


def check_ssl(address):
    try:
        if requests.get(f'https://{address}', timeout=10).status_code == 200:
            print(tabulate([('Connection is secure, HTTPS is responding',)]))
    except:
        print(tabulate([("There aren't any SSL",)]))


def whois_addr(address):
    try:
        print(tabulate([('WHOIS result', subprocess.getoutput(f'whois {address}'))]))
    except Exception as e:
        print(e)


def dig_address(address):
    try:
        a_record = pydig.query(f'{address}', 'A')
        txt_record = pydig.query(f'{address}', 'TXT')
        mx_record = pydig.query(f'{address}', 'MX')
        ns_records = pydig.query(f'{address}', 'NS')

        result_dict = {
            'A record': a_record,
            'TXT record': txt_record,
            'MX record': mx_record,
            'NS record': ns_records
        }

        print(tabulate(result_dict, headers=result_dict.keys()) + '\n')
    except Exception as e:
        print(e)


def run_tasks(data):
    task1 = threading.Thread(target=ping_addr, args=(data,))
    task2 = threading.Thread(target=check_ssl, args=(data,))

    if not re.search(regex_ip, get_arg):
        task3 = threading.Thread(target=whois_addr, args=(data,))
        task4 = threading.Thread(target=dig_address, args=(data,))

    task1.start()
    task2.start()
    
    if not re.search(regex_ip, get_arg):
        task3.start()
        task4.start()

    task1.join()
    task2.join()

    if not re.search(regex_ip, get_arg):
        task3.join()
        task4.join()



if re.search(regex_ip, get_arg):

    fqdn_addr = socket.getfqdn(f'{get_arg}')
    print(tabulate([('FQDN name is', socket.getfqdn(f'{get_arg}'))]))
    run_tasks(fqdn_addr)

else:

    ip_result = [("IP Address is", socket.gethostbyname(f"{get_arg}"))]
    print(tabulate(ip_result))
    run_tasks(get_arg)

