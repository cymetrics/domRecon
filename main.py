import argparse
from domain import Domain

def main():
    parser = argparse.ArgumentParser(
        description="Search for DNS records and check for simple domain-related vulnerabilities, such as zone transfers and takeovers. Also supports subdomain enumeration and recursive checks.",
        prog='domRecon',
        add_help=True
    )

    # must haves: one domain, a domain list, or help
    required_group = parser.add_mutually_exclusive_group(required=True)
    required_group.add_argument(
        '-d',
        '--domain',
        dest='domain',
        help='Target domain to check',
    )
    required_group.add_argument(
        '-l',
        '--domain-list',
        dest='domain_list',
        help='Text file with a list of target domains, with one domain on each line (WIP)',
    )
    
    # Checks
    parser.add_argument(
        '-a',
        '--all',
        action='store_true',
        help='Run all checks. Equivalent to -z -t -e',
    )
    parser.add_argument(
        '-z',
        '--zone',
        action='store_true',
        help='Checks for zone transfer',
    )
    parser.add_argument(
        '-t',
        '--takeover',
        action='store_true',
        help='Checks for subdomain takeover',
    )
    parser.add_argument(
        '-e',
        '--email',
        action='store_true',
        help='Checks for email authentication misconfigurations (WIP)',
    )
    
    # subdomain related
    parser.add_argument(
        '-s',
        '--subdomain',
        action='store_true',
        help='Construct list of subdomains candidates with both amass and bruteforce. Equivalent to -sa -sb',
    )
    parser.add_argument(
        '-sa',
        '--sub-amass',
        action='store_true',
        help='Construct list of subdomains candidates with amass',
    )
    parser.add_argument(
        '-sb',
        '--sub-brute',
        action='store_true',
        help='Construct list of subdomains candidates with bruteforce',
    )
    parser.add_argument(
        '--amass-path',
        default='amass',
        help='Path to the amass binary, ex: /usr/local/bin/amass, defaults to "amass"',
    )
    parser.add_argument(
        '--wordlist',
        help='Path to the wordlist for bruteforcing subdomains, defaults to the included "commonspeak.txt"',
    )
    parser.add_argument(
        '--massdns-path',
        default='massdns',
        help='Path of the massdns binary, ex: /usr/local/bin/massdns, defaults to "massdns"',
    )
    parser.add_argument(
        '--sublist',
        help='Path to your custom list of subdomains, with one domain on each line. Each domain will be resolved with massdns and passed on to further checks',
    )
    parser.add_argument(
        '-r',
        '--recurse',
        action='store_true',
        help='Run recursively for resolved subdomains, the -a -t -z -e options will be applied to discovered records. If no check options are specified, records are simply printed',
    )

    # other options
    parser.add_argument(
        '--ip6',
        action='store_true',
        help='Supports IPv6. If enabled, also checks for IPv6 addresses for domains. Also resolves AAAA records when enumerating subdomains.',
    )
    parser.add_argument(
        '-j',
        '--json',
        action='store_true',
        help='Print json format output. This effectively compiles all failed checks into json format. No warnings or passed checks are included.',
    )

    args = parser.parse_args()
    if args.domain:
        if args.all:
            dom = Domain(args.domain, True, True, True, args.recurse, args.ip6)
        else:
            dom = Domain(args.domain, args.zone, args.takeover, args.email, args.recurse, args.ip6)
        dom.check_service()

        if args.all or args.zone or args.takeover or args.email:
            dom.get_records()
            dom.check_records()
        
        if args.sublist or args.subdomain or args.sub_amass or args.sub_brute:
            if args.sublist:
                resolved = dom.resolve_subdomains(args.sublist, args.massdns_path)
            else:
                if args.subdomain:
                    candidates = dom.generate_subdomains(True, True, args.amass_path, args.wordlist)
                else:
                    candidates = dom.generate_subdomains(args.sub_amass, args.sub_brute, args.amass_path, args.wordlist)
                resolved = dom.resolve_subdomains(candidates, args.massdns_path)
            dom.check_subdomains(resolved)
    if args.json:
        print(dom.print_json())


if __name__ == "__main__":
    main()

