from record import Record
from utils import get_banner, query_record

MX_providers = {
    "google.com": "GSuite", 
    "googlemail.com": "GSuite",
    "outlook.com": "Microsoft",
    "amazonaws.com": "Amazon",
    "mailcloud.com.tw": "MailCloud",
    "messagelabs.com": "Broadcom",
    "mx.hover.com.cust.hostedemail.com": "Hover",
    "zoho.com": "Zoho",
    "yahoodns.net": "Yahoo",
    "protonmail.ch": "ProtonMail",
    "mail.ru": "Mail.ru",
    "icloud.com": "iCloud",
    "sendgrid.net": "SendGrid",
    "bluehost.com": "BlueHost"
}


class MXRecord(Record):
    rectype = 'MX'
    
    def __init__(self, rec, base, quiet):
        super().__init__(rec, base, quiet)
        self.record = self.record.split()[-1]       # leave out the priority number

    def check_provider(self, providers=None, base=None):
        super().check_provider(MX_providers, base=base)

        # no need to proceed if we already have a name
        if self.provider.is_set:
            return

        # else, try connecting to socket to grab banner
        ip_answer = query_record(self.record, 'A')

        for ip in ip_answer:
            try:
                port = 25
                banner = get_banner(ip,port)
            except Exception:
                try:
                    port = 587
                    banner = get_banner(ip,port)
                except Exception:
                    continue
            self.provider.set_banner(banner)


