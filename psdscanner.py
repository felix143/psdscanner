import socket
from queue import Queue
import threading
import requests
import sys
import json
import os
from bs4 import BeautifulSoup as bs


target = input('enter the domain name: ')
host = socket.gethostbyname(target)
queue = Queue()
open_ports = []

def portscan(port):
    try:
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.connect((host, port))
        return True
    except:
        return False

def fill_queue(port_list):
    for port in port_list:
        queue.put(port)

def worker():
    while not queue.empty():
        port = queue.get()
        if portscan(port):
            print("port {} is open".format(port))
            open_ports.append(port)

port_list = range(1, 100)
fill_queue(port_list)

thread_list = []

for t in range(10):
    thread = threading.Thread(target=worker)
    thread_list.append(thread)

for thread in thread_list:
    thread.start()

for thread in thread_list:
    thread.join()

print("Open ports are: ", open_ports)    


def enterRes(e):
    e = e.split('/', 1)[0]

    if e not in result:
        result.append(e)

def enumHackertarget():
    print('[!] Enumerating hackertarget.com')

    r = requests.get('https://api.hackertarget.com/hostsearch/?q=' + domain).text
    e = r.split('\n')

    print('\t - proceeding JSON output')

    for i in e:
        enterRes(i.split(',')[0])


def enumCertspotter():
    print('[!] Enumerating certspotter.com')

    r = requests.get('https://certspotter.com/api/v0/certs?domain=' + domain).text
    j = json.loads(r)

    print('\t - proceeding JSON output')

    for i in j:
        for e in i['dns_names']:
            if e.endswith('.' + domain) and not e.startswith('*'):
                enterRes(e)


def enumRiddler():
    print('[!] Enumerating riddler.io')

    r = requests.get('https://riddler.io/search?q=pld:' + domain).text
    s = bs(r, 'html.parser')
    e = s.findAll('td', class_='col-lg-5 col-md-5 col-sm-5')

    print('\t - proceeding HTML for filtering out the result')

    for i in e:
        enterRes(i.text.strip())


def enumCrt():
    print('[-] Enumerating crt.sh')

    r = requests.get('https://crt.sh/?q=%25' + domain).text
    s = bs(r, 'html.parser')

    try:
        e = s.findAll('table')[1].findAll('tr')
    except IndexError:
        print('\t - crt.sh did not respond, continueing')
    else:
        print('\t - proceeding HTML for filtering out the result')

        for i in e:
            e = i.findAll('td')

            try:
                e = e[4].text

                if e.endswith('.' + domain) and not e.startswith('*'):
                    enterRes(e)
            except IndexError:
                pass


def enumSecuritytrails():
    print('[!] Enumerating securitytrails.com')

    r = requests.get('https://securitytrails.com/list/apex_domain/' + domain).text
    s = bs(r, 'html.parser')
    e = s.findAll('td')

    print('\t - proceeding HTML for filtering out the result')

    for i in e:
        e = i.find('a')

        if e:
            enterRes(e.text)


def enumThreatminer():
    print('[!] Enumerating threatminer.org')

    try:
        r = requests.get('https://api.threatminer.org/v2/domain.php?q=' + domain + '&rt=5', timeout=6).text
        j = json.loads(r)

        print('\t - proceeding JSON output')

        for i in j['results']:
            enterRes(i)
    except requests.exceptions.Timeout:
        print('\t - API "api.threatminer.org/v2" looks down from here!')
        pass


def enumVirustotal():
    print('[!] Enumerating virustotal.com')

    r = requests.get('https://www.virustotal.com/ui/domains/' + domain + '/subdomains?limit=40').text
    j = json.loads(r)

    try:
        n = str(j['links']['next'])
        c = 1

        for i in j['data']:
            enterRes(i['id'])

        while type(n) is str:
            print('\t proceeding result set: ' + str(c))
            r = requests.get(n).text
            j = json.loads(r)

            for i in j['data']:
                enterRes(i['id'])

            try:
                n = str(j['links']['next'])
                c = c + 1
            except KeyError:
                break
    except KeyError:
        print('\t - result-set consists of < 40 entries')

        for i in j['data']:
            enterRes(i['id'])


def enumThreatcrowd():
    print('[!] Enumerating threadcrowd.com')

    r = requests.get('https://threatcrowd.org/searchApi/v2/domain/report/?domain=' + domain).text
    j = json.loads(r)

    print('\t - proceeding JSON output')

    if "subdomains" not in j:
        print('\t - JSON output seems to be empty!')
        return

    for e in j['subdomains']:
        enterRes(e)


def enumFindsubdomains():
    print('[!] Enumerating findsubdomains.com')

    r = requests.get('https://findsubdomains.com/subdomains-of/' + domain).text
    s = bs(r, 'html.parser')
    e = s.findAll('td', {'data-field': 'Domain'})

    print('\t - proceeding HTML for filtering out the result')

    for i in e:
        if i.get('title'):
            enterRes(i.get('title'))


def enumDNSDumpster():
    print('[!] Enumerating dnsdumpster.com')

    print('\t - requesting valid session')

    c = requests.Session()
    r = c.get('https://dnsdumpster.com').text
    h = {'Referer': 'https://dnsdumpster.com'}
    t = c.cookies.get_dict()['csrftoken']

    print('\t - got valid session: ' + t + ', proceeding output')

    r = c.post('https://dnsdumpster.com', data={'csrfmiddlewaretoken': t, 'targetip': domain}, headers=h).text
    s = bs(r, 'html.parser')
    t = s.findAll('table')[-1].findAll('td', class_='col-md-4')

    for i in t:
        t = i.text.split()[0]
        enterRes(t)
try:
    domain = target
except IndexError:
    print('[X] No domain passed')
    sys.exit()

result = []
output = open('results/' + domain + '.txt', 'w')

print('Target set to: ' + domain)

functions = [
    enumDNSDumpster,
    enumFindsubdomains,
    enumThreatcrowd,
    enumThreatminer,
    enumVirustotal,
    enumSecuritytrails,
    enumHackertarget,
    enumCrt,
    enumCertspotter,
    enumRiddler,
]

threads = []

if __name__ == '__main__':

    for f in functions:
        t = threading.Thread(target=f)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

filtered = list(filter(None, result))

try:
    for i in filtered:
        output.write(i + '\n')
finally:
    output.close()

print('[!] Finished, printing result:')

os.system('cat results/' + domain + '.txt')
print('[!] Counting ' + str(len(result)) + ' unique subdomains')
