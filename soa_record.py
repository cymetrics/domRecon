from record import Record


class SOARecord(Record):
    rectype = 'SOA'
    
    def check_provider(self, providers=None, base=None):
        pass