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
  "zone_walk": ["pixeltopic.com", "ftp.pixeltopic.com", "imap.pixeltopic.com"],
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

## Pitfalls

There are a few pitfalls that I encountered when bulk testing on domains. Here's some of them.

### Slow nameservers

When resolving subdomains, MassDNS queries against the **authoritative nameservers** for the most accurate results. However, depending on the how you host your nameservers, the reply speed may be drastically different. Popular cloud services such as AWS and Azure often have a lower latency, and self-hosted on-premise nameservers usually take longer. Total testing time with all options enabled could range from 20 to 100 minutes depending on network conditions.

Suggestion: Be patient, unless it's been stuck for more than two hours. In that case, you might have been banned. 

### Banned

You might be banned if the tool gives lots of errors, takes an extremely long time to complete, or produces no results even when you're sure the domain exists. There are two types of bans: 

First, your network/internet provider detected abnormal DNS traffic and cut you off. Consider deploying or running the tool with a cloud service. We had an Azure VM in use and ran bulk tests with it to avoid alerting internet providers.

Second, the target authoritative nameservers detected massive requests and banned your IP. Unless you're running multiple tests in parallel against a nameserver, this shouldn't be triggered too easily, but if it does, there's not much you can do except wait for the ban to expire or use another machine (with a different IP). Normally this might happen during subdomain enumeration, because the tool first resolves for A and CNAME records against all the candidates, and if you specify IPv6 or takeover, it resolves again but with AAAA and NS records. This means that for 100 candidates, it normally makes 100 DNS requests, but if all options are used, it makes 300 requests. In all, that's 3 times the original DNS traffic, not to mention that if you use the bruteforcing option there are *millions* of candidates. If you get banned, stop the tool because there won't be more progress. You can retry domain resolution using massDNS with other rate options to decrease the loading (might run longer) then feed the results into domrecon to run the checks.

### Endless subdomains

In e-commerce applications, you often can register your own shop on the platform and you will get a subdomain prefixed with your username. For example, if user `unipopcorn` opens a store on `beststore.com`, her site might be located on `unipopcorn.beststore.com`. Another example is web hosting services, such as GitHub pages. Since the domain is hosted and managed as a subdomain, it shows up during subdomain enumeration, but it's NOT what we were trying to find (we are digging for secret/dangerous domains). The tool can't distinguish between subdomains, so it's recommended to not run the tool on such websites, otherwise the tool might run for hours and you will only get tons of false positives.