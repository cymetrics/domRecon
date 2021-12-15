from record import Record

class TXTRecord(Record):
    rectype = 'TXT'
    
    def check_provider(self, providers=None, base=None):
        pass