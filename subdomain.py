from os import path, makedirs
import subprocess

# output files
OUTPUT_DIR = 'output'
amass_out = path.join(OUTPUT_DIR, 'amass.txt')              # output from amass passive scan
brute_out = path.join(OUTPUT_DIR, 'brute.txt')              # domains generated with commonspeak2
final_out = path.join(OUTPUT_DIR, 'final.txt')              # final candidates

resolved = path.join(OUTPUT_DIR, 'resolved.txt')            # resolved subdomains with massdns

def generate(domain, amass, brute, amass_path, wordlist):
    # make OUTPUT_DIR if it doesn't exist yet before we run the tools
    makedirs(OUTPUT_DIR, exist_ok=True)

    if amass:
        print('[*] Gathering subdomains with Amass')
        rawdomains = amass_out    
        cmd = f"{amass_path} enum -timeout 15 --passive -d {domain} > {amass_out}"
        try:
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.SubprocessError as e:
            print(f'Subprocess error in [amass]: {e}')
    if brute:
        print('[*] Gathering subdomains with commonspeak')
        rawdomains = brute_out
        cmd = f"awk 'NF{{print $0 \".{domain}\"}}' {wordlist} > {brute_out}"
        try:
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.SubprocessError as e:
            print(f'Subprocess error in [brute]: {e}')
    
    if amass and brute:
        print('[*] Merging Amass and commonspeak')
        rawdomains = final_out
        cmd = f"awk '!seen[$0]++' {amass_out} {brute_out} > {rawdomains}"
        try:
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.SubprocessError as e:
            print(f'Subprocess error in [merging]: {e}')
    
    return rawdomains


def resolve(resolver, sublist, massdns_path, takeover):
    print('[*] Resolving subdomains (A) with massDNS')

    # cmd = f"{massdns_path} -r {resolver} -q -t A -o S {sublist} | awk '{{x=$1 \" \" $2;a[x]=x in a?a[x] \",\" $3 : $3}}END{{for(i in a) print i \" \"a[i]}}' | sort > {resolved} "
    cmd = f"{massdns_path} -r {resolver} -q -t A -o Sn {sublist} > {resolved}"
    try:
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.SubprocessError as e:
        print(f'Subprocess error in [massdns] when resolving A records: {e}')
    
    if takeover:
        print('[*] Resolving subdomains (NS, CNAME) with massDNS')
        # cmd = f"{massdns_path} -r {resolver} -q -t NS -o Sn {sublist} | awk '{{x=$1 \" \" $2;a[x]=x in a?a[x] \",\" $3 : $3}}END{{for(i in a) print i \" \"a[i]}}' >> {resolved}; sort -u {resolved} -o {resolved}  "
        cmd = f"{massdns_path} -r {resolver} -q -t NS -o Sn {sublist} >> {resolved}"
        try:
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.SubprocessError as e:
            print(f'Subprocess error in [massdns] when resolving NS records: {e}')
    
    # clean up a bit
    cmd = f"sort -u {resolved} | awk '{{x=$1 \" \" $2;a[x]=x in a?a[x] \",\" $3 : $3}}END{{for(i in a) print i \" \"a[i]}}' | sort -o {resolved}"
    try:
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.SubprocessError as e:
        print(f'Subprocess error when resolving cleaning up resolved.txt: {e}')
    
    return resolved