# DomRecon

## Simple workflow for DNS recon  

DomRecon is a simple tool for checking DNS records, enumerating subdomains, and testing subdomains for vulnerabilities.

I developed this tool to facilitate my DNS recon process for bug bounties, because I was tired of constantly 'digging' for records. I wanted to quickly:

1. fetch a domain's DNS records and check its third party providers
2. enumerate subdomains reliably
3. check base domain and subdomains for low hanging fruit: zone transfers and domain takeovers

The project takes inspiration from and incorporates many well-known tools and projects, here just to name a few:

* [Amass](https://github.com/OWASP/Amass)
* [MassDNS](https://github.com/blechschmidt/massdns)
* [commonspeak2-wordlist](https://github.com/assetnote/commonspeak2-wordlists)
* [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
* [can-i-take-over-dns](https://github.com/indianajson/can-i-take-over-dns)
* [Patrik Hudak's Blog](https://0xpatrik.com/)

I went through tons of subdomain takeover projects on Github and merged their data into DomRecon. I also double-checked most of the services and their vulnerability statuses since vendors are actively developing their products and some of the discussions threads and information on other projects are outdated. I also included additional services that I encountered during testing that were undocumented in any discussions or vulnerability reports. As of this writing, you can consider [CNAME takeover list](./cname-tko.json) and [NS takeover list](./ns-tko.json) as a compiled and verified source for checking domain takeovers. Of course, they are by no means complete, but I'll continually check the referenced sources and update my list.

Also, more checks will be added! I have another DMARC and SPF checker tool that I've yet to incorporate into DomRecon. Here is a list of TODOs (that'll grow after time):

- [x] support IPv6
- [x] zone walk
- [ ] MX checks - takeover
- [ ] TXT checks - DMARC, SPF
- [ ] TXT checks - information leakage(?)

## Usage

**Dependencies: Amass and MassDNS**

```txt
Usage: domRecon [-h] (-d DOMAIN | -l DOMAIN_LIST) [-a] [-z] [-t] [-e] [-s]
                [-sa] [-sb] [--amass-path AMASS_PATH] [--wordlist WORDLIST]
                [--massdns-path MASSDNS_PATH] [--sublist SUBLIST] [-r] [-j]

Search for DNS records and check for simple domain-related vulnerabilities,
such as zone transfers and takeovers. Also supports subdomain enumeration and
recursive checks.

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Target domain to check
  -l DOMAIN_LIST, --domain-list DOMAIN_LIST
                        Text file with a list of target domains, with one
                        domain on each line (WIP)
  -a, --all             Run all checks. Equivalent to -z -t -e
  -z, --zone            Checks for zone transfer
  -t, --takeover        Checks for subdomain takeover
  -e, --email           Checks for email authentication misconfigurations
                        (WIP)
  -s, --subdomain       Construct list of subdomains candidates with both
                        amass and bruteforce. Equivalent to -sa -sb
  -sa, --sub-amass      Construct list of subdomains candidates with amass
  -sb, --sub-brute      Construct list of subdomains candidates with
                        bruteforce
  --amass-path AMASS_PATH
                        Path to the amass binary, ex: /usr/local/bin/amass,
                        defaults to "amass"
  --wordlist WORDLIST   Path to the wordlist for bruteforcing subdomains,
                        defaults to the included "commonspeak.txt"
  --massdns-path MASSDNS_PATH
                        Path of the massdns binary, ex:
                        /usr/local/bin/massdns, defaults to "massdns"
  --sublist SUBLIST     Path to your custom list of subdomains, with one
                        domain on each line. Each domain will be resolved with
                        massdns and passed on to further checks
  -r, --recurse         Run recursively for resolved subdomains, the -a -t -z
                        -e options will be applied to discovered records. If
                        no check options are specified, records are simply
                        printed
  -j, --json            Print json format output. This effectively compiles
                        all failed checks into json format. No warnings or
                        passed checks are included.
```

For example, to check everything on the base domain and all enumerated subdomains:

`python3 main.py -d example.com -a -r -s`

To check my own list of subdomains for `example.com`:

`python3 main.py -d example.com -a -r --sublist ~/my_sub.txt`

If Amass and MassDNS are located in `/bin`:

`python3 main.py -d example.com -a -r -s --amass-path /bin/amass --massdns-path /bin/massdns`

Output files from subdomain enumeration and resolving will be stored in the `output/` directory.
* Amass: `output/amass.txt`
* Brute: `output/brute.txt`
* Merged list of Amass and brute: `output/final.txt`
* Resolved subdomains and records: `output/resolved.txt`

If the resolved results exceed 200 records, subdomain checks will not cover all records. When `--recurse` is set, only CNAME and NS records will be checked for specified vulnerabilities; otherwise, only the first 50 records will be shown in output.

Please check `resolved.txt` for complete results.

If you want to output discovered vulnerabilities in json format, use the `-j` option. The format is:

```json
{
  "zone_transfer": ["nsztm2.digi.ninja (34.225.33.2 Found zone file!\\nzonetransfer.me. 7200 IN SOA nsztm1.digi.ninja. robin.digi.ninja. 2019100801 172800 900 1209600 3600"], 
  "takeover": []
}
```

## Docker

The dockerfile installs both amass and massdns under the `/bin` directory. 

To build the docker, run:

`docker build -t domrecon .`

To spin up the docker and check on a domain, e.g cymetrics.io, run:

`docker run --rm -it domrecon -d cymetrics.io -a -sa --amass-path /bin/amass --massdns-path /bin/massdns`

To help with automation, here's an example to check a list of domains and save the output:

```bash
declare -a arr=("cymetrics.io" "onedegree.hk" "onedegree.global")

## now loop through the above array
for i in "${arr[@]}"
do
    echo "Working on $i ..."
    docker run --rm -it domrecon -d $i -a -sa --amass-path /bin/amass --massdns-path /bin/massdns > ${i}_out.txt
    echo "Done with $i, output in ${i}_out.txt"
done
```