from record import Record, CheckResults
import json
from utils import query_existence, headers
import requests

requests.packages.urllib3.disable_warnings()


takeover_file = 'cname-tko.json'

class CNAMERecord(Record):
    rectype = 'CNAME'

    def check_provider(self, providers=None, base=None):
        # cname points to another self-hosted domain -> you're your own provider!
        if self.record.endswith(base):
            self.provider.set_lookup('self')
            super().check_provider()
        else:
            CNAME_provider = dict()
            with open(takeover_file, 'r') as infile:
                data = json.load(infile)
            for entry in data:
                for cname in entry['Cname']:
                    CNAME_provider[cname] = entry['Engine']
            super().check_provider(providers=CNAME_provider, base=base)
    
    def check_takeover(self):
        '''
        if lookup did not return result (don't know provider) -> unknown
        if provider is 'not vulnerable' -> pass
        else 
            if dns query return NX_DOMAIN -> fail
            else 
                if fingerprint in response(both http and https) -> fail
                else -> pass
        '''
        check_name = 'takeover'
        msg = None
        service = self.provider.get_lookup
        if not service:
            msg = (CheckResults.WARNING, f"{self.record} (provider unknown)")
            self.results[check_name] = msg
            self.print_console(msg)
            return
        if service == 'self':
            msg = (CheckResults.INFO, f"{self.record} ({service}, self-hosted)")
            self.results[check_name] = msg
            self.print_console(msg)
            return

        with open(takeover_file, 'r') as infile:
            data = json.load(infile)
        
        for entry in data:
            if service == entry['Engine']:
                if entry['Status'].lower() == 'not vulnerable':
                    msg = (CheckResults.PASS, f"{self.record} ({service}, GOOD, not vulnerable)")
                else:
                    if query_existence(self.record):
                        # found domain, checking fingerprint (try both http and https)
                        protols = ['http://', 'https://']
                        for protol in protols:
                            url = protol + self.base
                            try:
                                resp = requests.get(url, headers=headers, timeout=5, verify=False)
                                if entry['Fingerprint'] in resp.text:
                                    msg = (CheckResults.FAIL, f"{self.record} ({service}, found fingerprint)" + self.get_details(entry))
                                    break
                            except:
                                # if for any reason we can't connect, then there probably isn't a website here
                                # pass
                                msg = (CheckResults.WARNING, f"{self.record} ({service}, unable to connect)" + self.get_details(entry))
                        # no fingerprint found, this running service is valid
                        if not msg:
                            msg = (CheckResults.PASS, f"{self.record} ({service}, GOOD, service valid)")
                    else:
                        msg = (CheckResults.FAIL, f"{self.record} ({service}, NXDOMAIN)" + self.get_details(entry))
                
                if msg:
                    self.results[check_name] = msg
                    self.print_console(msg)
                return
        
    def get_details(self, data):
        s = ""
        for k in ['Discussion', 'Documentation']:
            if data[k]:
                s += f"\n\t{k}: {data[k]}"
        return s
        
        
        