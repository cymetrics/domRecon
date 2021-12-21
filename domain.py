from os import path, makedirs
from requests.models import HTTPError
from utils import query_record, headers
from output import print_header, bcolors
import requests
import subprocess

requests.packages.urllib3.disable_warnings()

LIST_DIR = 'lists'

# output files
OUTPUT_DIR = 'output'
amass_out = path.join(OUTPUT_DIR, 'amass.txt')              # output from amass passive scan
brute_out = path.join(OUTPUT_DIR, 'brute.txt')              # domains generated with commonspeak2
resolved = path.join(OUTPUT_DIR, 'resolved.txt')            # resolved subdomains with massdns

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

    def get_records(self):
        # TODO: this part is currently useless, since we don;t call get_records() anymore for subdomains
        # if domain doesn't exist (no A no IP) or is a subdomain, we only check NS and CNAME records for takeover
        # if self.sub or not query_existence(self.domain):
        #     quiet = True
        #     if self.zone:
        #         to_fetch = ['NS']
        #     if self.takeover:
        #         to_fetch = ['NS','CNAME']
        #     else:
        #         return
        # else:
        if not self.ip:
            self.add_ips(query_record(self.domain, 'A', timeout=5.0))

        to_fetch = self.records.keys()
        quiet = False

        for tp in to_fetch:
            # fetch record
            print_header(tp + " records", self.sub)
            
            ans = query_record(self.domain, tp, timeout=5.0)
            for rec in ans:
                self.add_record(tp, rec, quiet, self.domain)

    
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
        
        # think about checking email...

    def generate_subdomains(self, amass, brute, amass_path, massdns_path, wordlist):
        print_header("Fetching subdomains", self.sub)

        # make OUTPUT_DIR if it doesn't exist yet before we run the tools
        makedirs(OUTPUT_DIR, exist_ok=True)
        if not wordlist:
            wordlist = path.join(LIST_DIR, 'commonspeak.txt')

        if not amass and not brute:
            print('No methods for searching subdomains!\nEither provide a subdomain list or specify at least one of -sa (amass) -sb (bruteforce)!')
            return

        if amass:
            print('[*] Gathering subdomains with Amass')
            rawdomains = amass_out    
            cmd = f"{amass_path} enum -timeout 15 --passive -d {self.domain} > {amass_out}"
            try:
                subprocess.run(cmd, shell=True, check=True)
            except subprocess.SubprocessError as e:
                print(f'Subprocess error in [amass]: {e}')
        if brute:
            print('[*] Gathering subdomains with commonspeak')
            rawdomains = brute_out
            cmd = f"awk 'NF{{print $0 \".{self.domain}\"}}' {wordlist} > {brute_out}"
            try:
                subprocess.run(cmd, shell=True, check=True)
            except subprocess.SubprocessError as e:
                print(f'Subprocess error in [brute]: {e}')
        
        if amass and brute:
            print('[*] Merging Amass and commonspeak')
            rawdomains = path.join(OUTPUT_DIR, 'final.txt')
            cmd = f"awk '!seen[$0]++' {amass_out} {brute_out} > {rawdomains}"
            try:
                subprocess.run(cmd, shell=True, check=True)
            except subprocess.SubprocessError as e:
                print(f'Subprocess error in [merging]: {e}')
        
        self.resolve_subdomains(rawdomains, massdns_path)


    def resolve_subdomains(self, sublist, massdns_path):  
        print('[*] Resolving subdomains (A) with massDNS')

        # default use authoritative nameservers
        nameservers = '\n'.join(list(map(lambda i: '\n'.join(query_record(i.record, "A")), self.records["NS"])))
        if nameservers:
            resolver = path.join(LIST_DIR, 'auth_ns.txt')
            with open(resolver, 'w') as outfile:
                outfile.write(nameservers)
        else:
            resolver = path.join(LIST_DIR, 'resolver.txt')

        # cmd = f"{massdns_path} -r {resolver} -q -t A -o S {sublist} | awk '{{x=$1 \" \" $2;a[x]=x in a?a[x] \",\" $3 : $3}}END{{for(i in a) print i \" \"a[i]}}' | sort > {resolved} "
        cmd = f"{massdns_path} -r {resolver} -q -t A -o Sn {sublist} > {resolved}"
        try:
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.SubprocessError as e:
            print(f'Subprocess error in [massdns] when resolving A records: {e}')
        
        if self.takeover:
            print('[*] Resolving subdomains (NS, CNAME) with massDNS')
            # cmd = f"{massdns_path} -r {resolver} -q -t NS -o Sn {sublist} | awk '{{x=$1 \" \" $2;a[x]=x in a?a[x] \",\" $3 : $3}}END{{for(i in a) print i \" \"a[i]}}' >> {resolved}; sort -u {resolved} -o {resolved}  "
            cmd = f"{massdns_path} -r {resolver} -q -t NS -o Sn {sublist} >> {resolved}"
            try:
                subprocess.run(cmd, shell=True, check=True)
            except subprocess.SubprocessError as e:
                print(f'Subprocess error in [massdns] when resolving NS records: {e}')
        
        # clean up a bit
        cmd = f"sort -u {resolved} | awk '{{x=$1 \" \" $2;a[x]=x in a?a[x] \",\" $3 : $3}}END{{for(i in a) print i \" \"a[i]}}' | sort -o {resolved}"
        try:
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.SubprocessError as e:
            print(f'Subprocess error when resolving cleaning up resolved.txt: {e}')


            
    def check_subdomains(self):
        print_header("Checking subdomains", self.sub)

        with open(resolved, 'r') as infile:
            lines = infile.readlines()
            print(f'[*] Found active records: {len(lines)} (output in {resolved})')
        
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
                print(f'[*] Too many lines... checking only first 50 lines here. For full output see {resolved}')
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

    def add_subdomain(self, dom):
        if dom is not None:
            dom.check_records()
            dom.check_service()
            dom.print_basic()
            self.subdomains.append(dom)


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
