from os import path
import json
from requests.models import HTTPError
from utils import query_record, headers
from output import print_header, bcolors
from subdomain import generate, resolve
from record import CheckResults
import requests

requests.packages.urllib3.disable_warnings()

LIST_DIR = 'lists'
class Domain():
    def __init__(self, domain, zone, takeover, email, recurse, sub=False, ip='') -> None:
        self.domain = domain.lower().strip()
        self.ip = set(ip.split(',')) if ip else set()
        self.records = {
            "SOA": [],
            "NS": [],
            "MX": [],
            "CNAME": [],
            "TXT": [],
        }
        self.subdomains = []

        # store the arg flags
        self.web = ''
        self.zone = zone
        self.takeover = takeover
        self.email = email
        self.recurse = recurse
        self.sub = sub

    '''Query records with DNS'''
    def get_records(self):
        if not self.ip:
            self.add_ips(query_record(self.domain, 'A', timeout=5.0))

        to_fetch = self.records.keys()
        quiet = False

        for tp in to_fetch:
            print_header(tp + " records", self.sub)
            ans = query_record(self.domain, tp, timeout=5.0)
            for rec in ans:
                self.add_record(tp, rec, quiet, self.domain)

    '''Add records to record list'''
    def add_record(self, tp, rec, quiet, base=None):
        # initiate record
        modname = tp.lower() + "_record"
        clsname = tp.upper() + "Record"
        module = __import__(modname)
        cls = getattr(module, clsname)
        new_rec = cls(rec, self.domain, quiet=quiet)
        new_rec.check_provider(base=base)
        if not quiet:
            new_rec.print_console()
        self.records[tp].append(new_rec)

    def add_ips(self, ips):
        self.ip.update(ips)

    '''Check reocrds for vulns, will expand as checks grow'''
    def check_records(self):
        if self.zone:
            print_header("Zone Transfer", self.sub)
            for rec in self.records['NS']:
                rec.check_zone_transfer()

        if self.takeover:
            print_header("NS Subdomain Takeover", self.sub)
            for rec in self.records['NS']:
                rec.check_takeover()  
            print_header("CNAME Subdomain Takeover", self.sub)
            for rec in self.records['CNAME']:
                rec.check_takeover()
        
    '''Generate a candidate list of subdomains, using Amass, CommonSpeak, and output from NS checks'''
    def generate_subdomains(self, amass, brute, amass_path, wordlist):
        print_header("Fetching subdomains", self.sub)

        if not wordlist:
            wordlist = path.join(LIST_DIR, 'commonspeak.txt')
        if not amass and not brute:
            print('No methods for searching subdomains!\nEither provide a subdomain list or specify at least one of -sa (amass) -sb (bruteforce)!')
            return

        rawdomains = generate(self.domain, amass, brute, amass_path, wordlist)
        
        # add ns vulns to list, ex: zone transfer and zone walk 
        # note: traverse ns records -> parse msg for zone stuff is applicable -> append to rawdomains
        doms = list()
        for rec in self.records["NS"]:
            msg = rec.results.get("zone_transfer")
            if msg is not None and msg[0] == CheckResults.FAIL:
                doms.extend(list(map(lambda x: x.split()[0].strip(".")+"\n", msg[1].split("\n")[1:-1])))
        if doms:
            with open(rawdomains, 'a') as raw:
                raw.writelines(doms)
        return rawdomains

    '''Resolve subdomains using MassDNS'''
    def resolve_subdomains(self, sublist, massdns_path):  
        # default use authoritative nameservers
        nameservers = '\n'.join(list(map(lambda i: '\n'.join(filter(None,query_record(i.record, "A"))), self.records["NS"])))
        if nameservers:
            resolver = path.join(LIST_DIR, 'auth_ns.txt')
            with open(resolver, 'w') as outfile:
                outfile.write(nameservers)
        else:
            resolver = path.join(LIST_DIR, 'resolver.txt')

        resolved_list = resolve(resolver, sublist, massdns_path, self.takeover)
        return resolved_list

    '''Check subdomains for common vulns and print with colors'''
    def check_subdomains(self, resolved_list):
        print_header("Checking subdomains", self.sub)

        with open(resolved_list, 'r') as infile:
            lines = infile.readlines()
            print(f'[*] Found active records: {len(lines)} (output in {resolved_list})')
        
        if len(lines) > 200:
            # we grep the cname and ns records if takeover or zone transfer checks are specified
            if self.recurse:
                if self.zone:
                    to_check = ["NS"]
                if self.takeover:
                    to_check = ["CNAME", "NS"]
                if to_check:
                    lines = list(filter(lambda i: i.split()[1] in to_check, lines))
                    print(f'[*] Too many lines... we only check CNAME and NS records {len(lines)}')
            else:
                print(f'[*] Too many lines... checking only first 50 lines here. For full output see {resolved_list}')
                lines = lines[:50]

        prev = None
        for line in lines:
            tok = [i.strip().strip('.') for i in line.split()]
            # sometimes we just get the same domain... ignore it
            if tok[0] == self.domain:
                continue

            # option 2: if domain exists, don't create new one. Add records directly and modify printing
            if prev is not None and prev.domain == tok[0]:
                if tok[1] == 'A':
                    prev.add_ips([tok[2]])
                else:
                    for rec in tok[2].split(','):
                        prev.add_record(tok[1], rec, True, self.domain)
            else:
                # domain doesn't exist, create a new one
                if tok[1] == 'A':
                    if self.recurse:
                        dom = Domain(tok[0], zone=self.zone, takeover=self.takeover, email=self.email, recurse=False, sub=True, ip=tok[2])
                    else:
                        dom = Domain(tok[0], zone=False, takeover=False, email=False, recurse=False, sub=True, ip=tok[2])
                elif tok[1] == 'CNAME' or tok[1] == 'NS':
                    if self.recurse:
                        dom = Domain(tok[0], zone=self.zone, takeover=self.takeover, email=self.email, recurse=False, sub=True)
                    else:
                        dom = Domain(tok[0], zone=False, takeover=False, email=False, recurse=False, sub=True)
                    for rec in tok[2].split(','):
                        dom.add_record(tok[1], rec, True, self.domain)
                    # resolve ip 
                    dom.add_ips(query_record(tok[0], 'A'))
                else:
                    print(f'Unexpected record type! {line}')
                
                self.add_subdomain(prev)
                # point to last
                prev = dom
        # add last (missed in loop)
        self.add_subdomain(prev)

    '''Add subdomains to subdomain list'''
    def add_subdomain(self, dom):
        if dom is not None:
            dom.check_records()
            dom.check_service()
            dom.print_basic()
            self.subdomains.append(dom)

    '''Check if HTTP/HTTPS connection is available to determine if it is a webserver'''
    def check_service(self):
        protos = ['https://', 'http://']
        for proto in protos:
            url = proto + self.domain
            try:
                _ = requests.get(url, headers=headers, timeout=3, verify=False)
                self.web = url
                break
            except (requests.exceptions.RequestException, HTTPError):
                # covers requests.exceptions.ConnectionError, requests.exceptions.Timeout, requests.exceptions.SSLError ....
                # just treat them as failed 
                pass

    '''Used to print brief information on subdomains'''
    def print_basic(self):
        if self.ip:
            ips = ', '.join(self.ip)
            if not self.web:
                print(bcolors.OKGREEN + self.domain + bcolors.ENDC + f" ({ips})")
            else:
                print(bcolors.OKGREEN + self.domain + bcolors.ENDC + f" ({ips}, {self.web})")
        else:
            print(bcolors.WARNING + self.domain + f" (NXDOMAIN)" + bcolors.ENDC)
        
        checklist = ["NS", "CNAME"] # expand this list when we have more checks
        for checked in checklist:
            for rec in self.records[checked]:
                rec.print_results()

    '''Used to print identified risks in json formatted output. Only FAILED checks are printed.'''
    def print_json(self):
        json_out = {
            "zone_transfer": [],
            "takeover": [],
        }
        for rec in self.records['NS']:
            z = rec.results.get('zone_transfer')
            if z is not None and z[0] == CheckResults.FAIL:
                json_out['zone_transfer'].append(z[1])
            z = rec.results.get('takeover')
            if z is not None and z[0] == CheckResults.FAIL:
                json_out['takeover'].append(z[1])
        for rec in self.records['CNAME']:
            z = rec.results.get('takeover')
            if z is not None and z[0] == CheckResults.FAIL:
                json_out['takeover'].append(z[1])
        
        return json.dumps(json_out)