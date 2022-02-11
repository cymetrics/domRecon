from output import bcolors
import whois
from enum import Enum

class CheckResults(Enum):
    PASS = 'pass'
    FAIL = 'fail'
    WARNING = 'warn'
    INFO = 'info'

class Provider:
    def __init__(self):
        self.lookup = ''
        self.org = ''
        self.registrar = ''
        self.banner = ''
        self.subdata = None
    
    def set_lookup(self, val):
        self.lookup = val

    def set_whois(self, org, reg):
        self.org = org
        self.registrar = reg

    def set_banner(self, val):
        self.banner = val

    def set_subdata(self, d):
        self.subdata = d

    @property
    def get_lookup(self):
        return self.lookup

    @property
    def is_set(self):
        return self.org or self.lookup or self.banner
    
    def print(self):
        if not self.is_set and not self.registrar:
            return ''
        else:
            tok = [' (']
            if self.lookup:
                tok.append(self.lookup + ',')
            if self.org:
                tok.append('OrgName: ' + self.org + ',')
            if self.registrar:
                tok.append('Registrar: ' + self.registrar + ',')
            if self.banner:
                tok.append('Banner: ' + self.banner)
            tok.append(')')
            return ' '.join(tok)

class Record():
    rectype = ''

    def __init__(self, rec, base, quiet=False):
        self.record = rec.lower().strip().strip('.')
        self.base = base.lower()
        self.provider = Provider()
        self.results = {}
        self.quiet = quiet

    def print_console(self, data=None):
        if self.quiet:
            return
        # if no data -> regular printing for get_record()
        if data is None:
            print(bcolors.OKGREEN + self.record + bcolors.OKBLUE + self.provider.print() + bcolors.ENDC)
        # if data -> printing results from record check
        else:
            print(self.get_color(data[0]), data[1], bcolors.ENDC)

    def print_results(self):
        for (k,v) in self.results.items():
            # if v[0] != CheckResults.PASS:
            print(f"\t{self.rectype} ({k}):", self.get_color(v[0]), v[1], bcolors.ENDC)

    def get_color(self, res):
        if res == CheckResults.PASS:
            color = bcolors.OKCYAN
        elif res == CheckResults.FAIL:
            color = bcolors.FAIL
        elif res == CheckResults.WARNING:
            color = bcolors.WARNING
        else:
            color = bcolors.PLAIN
        return color

    def check_provider(self, providers=None, base=None):
        import time
        time.sleep(1)
        if providers is not None:
            # list lookup
            for (k,v) in providers.items():
                if k in self.record:
                    self.provider.set_lookup(v)
                    break
        # check whois for arin info
        try:
            res = whois.whois(self.record)
            self.provider.set_whois(res.org, res.registrar)
        except whois.parser.PywhoisError:
            # means NXDOMAIN, but we won't do anything here
            pass

