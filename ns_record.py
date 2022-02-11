from record import Record, CheckResults
from utils import query_dns
from dns import zone, resolver, query, rdatatype
import json

takeover_file = 'ns-tko.json'

class NSRecord(Record):
    rectype = 'NS'

    def check_provider(self, providers=None, base=None):
        # ns points to another self-hosted domain -> you're your own provider!
        if self.record.endswith(base):
            self.provider.set_lookup('self')
            super().check_provider()
        else:
            NS_providers = dict()
            with open(takeover_file, 'r') as infile:
                data = json.load(infile)
            for entry in data:
                for ns in entry['NS']:
                    NS_providers[ns] = entry['Engine']
            super().check_provider(providers=NS_providers, base=base)

    def check_zone_transfer(self):
        check_name = 'zone_transfer'
        try:
            ip_answer = query_dns(self.record, rdatatype.A, timeout=5.0)
        except (resolver.NXDOMAIN, resolver.NoAnswer, resolver.Timeout):
            msg = (CheckResults.WARNING, f"{self.record} ( No IP found, takeover possible! )")
            self.results[check_name] = msg
            self.print_console(msg)
            return
        
        for ip in ip_answer:
            print(ip)
            try:
                nszone = zone.from_xfr(query.xfr(str(ip), self.base, timeout=5))
                # no error means we successfully performed zone transfer!
                # rs = ["Found zone file!\n"]
                # for node in nszone:
                #     for rdset in node:
                #         r = rdset.to_text(relativize=False)
                #         print(r)
                #         rs.append(r)
                msg = (CheckResults.FAIL, f"{self.record} ({ip} Found zone file!\n" + nszone.to_text(relativize=False) + " )")
                        
            except Exception as e:
                print(e)
                msg = (CheckResults.PASS, f"{self.record} ({ip} GOOD, refused zone transfer)")

            self.results[check_name] = msg
            self.print_console(msg)

    def check_takeover(self):
        '''
        if nameserver is NXDOMAIN -> takeover possible
        if weird status (NoNameservers: SERVFAIL or REFUSED) when resolving against nameserver -> takeover possible
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
            if service in entry['Engine']:
                if entry['Status'].lower() == 'not vulnerable':
                    msg = (CheckResults.PASS, f"{self.record} ({service} GOOD, not vulnerable)")
                    break
        
        # unknown service or vulnerable service
        if not msg:
            try:
                ips = query_dns(self.record, rdatatype.A)
                try:
                    _ = query_dns(self.base, rdatatype.A, nameservers=ips, timeout=5.0)
                except resolver.NoNameservers as e:
                    statuses = ["REFUSED", "SERVFAIL"]
                    for status in statuses:
                        if status in e.msg:
                            msg = (CheckResults.FAIL, f"{self.record} ({service} {status}, possible takeover if you can register!)")
                            break
                # this includes NoAnswer, which is expected if the input is a root domain with no actual IP
                except Exception as e:
                    pass
                if not msg:
                    msg = (CheckResults.PASS, f"{self.record} ({service} GOOD, service valid)")
                
            except (resolver.NXDOMAIN, resolver.NoAnswer):
                msg = (CheckResults.FAIL, f"{self.record} ({service} NXDOMAIN, possible takeover if you can register!)")
            except Exception as e:
                print(f'Exception checking nameservers. {e}')
        
        if msg:
            self.results[check_name] = msg
            self.print_console(msg)


if __name__ == "__main__":
    rec = NSRecord("intns1.zonetransfer.me", "zonetransfer.me")
    rec.check_zone_transfer()