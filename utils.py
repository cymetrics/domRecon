import socket
import dns.resolver
import dns.rdatatype

headers = {'user-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0'}

def get_banner(ip,port):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((ip,port))
    banner = s.recv(1024).strip().decode('utf-8')
    return banner

def query_dns(domain, record_type, nameservers=None, timeout=2.0):
    domain = str(domain).lower()

    resolver = dns.resolver.Resolver()
    timeout = float(timeout)
    if nameservers is None:
        nameservers = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "2606:4700:4700::1111", "2606:4700:4700::1001"]
    resolver.nameservers = nameservers
    resolver.timeout = timeout
    resolver.lifetime = timeout
    if record_type == dns.rdatatype.TXT:
        resource_records = list(map(
            lambda r: r.strings,
            resolver.query(domain, record_type, lifetime=timeout)))
        _resource_record = [
            resource_record[0][:0].join(resource_record)
            for resource_record in resource_records if resource_record]
        records = [r.decode() for r in _resource_record]
    else:
        records = list(map(
            lambda r: r.to_text().replace('"', '').rstrip("."),
            resolver.query(domain, record_type, lifetime=timeout)))

    return records


def query_record(domain, record_type, nameservers=None, timeout=2.0):
    res = []
    try:
        res = query_dns(domain, record_type, nameservers, timeout)
    except dns.resolver.NoAnswer:
        pass
    except Exception as e:
        print(f'Exception querying {record_type} records for {domain}. {e}')
    return res

def query_existence(domain, nameservers=None, timeout=3.0):
    try:
        _ = query_dns(domain, "A", nameservers, timeout)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers): 
        return False
    except Exception as e:
        print(f'Exception checking existence for {domain}. {e}')
        return False
    return True

def merge():
    import json
    with open('fingerprints.json', 'r') as infile:
        data = json.load(infile)
    # new = sorted(data, key=lambda i: i['service'])
    # with open('test.json', 'w') as outfile:
    #     json.dump(new, outfile, indent=4)
    # sorted_service = sorted(list(map(lambda x: x['service'], data)))
    # print(sorted_service)

if __name__ == '__main__':
    merge()