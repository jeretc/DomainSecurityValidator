# Author : Jeret Christopher @ M0du5

import dns.resolver
import dkim
import re
from colorama import Fore, Style
import pyfiglet

def print_banner():
    banner_text = pyfiglet.figlet_format("Domain Security Validator", font="slant")
    print(banner_text)

def print_greetings():
    print("Welcome to the Domain Security Validator!")
    print("This utility will check the following records for a domain:\n")
    print("- SPF (Sender Policy Framework)")
    print("- DMARC (Domain-based Message Authentication, Reporting, and Conformance)")
    print("- DKIM (DomainKeys Identified Mail)\n")
    print("Let's get started!\n")

def check_spf(domain):
    try:
        spf_records = dns.resolver.resolve(domain, 'TXT')
        for record in spf_records:
            if record.strings and b'v=spf1' in record.strings[0]:
                return record.strings[0].decode()
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    return None

def check_dmarc(domain):
    try:
        dmarc_records = dns.resolver.resolve('_dmarc.' + domain, 'TXT')
        for record in dmarc_records:
            if record.strings and b'v=DMARC1' in record.strings[0]:
                return record.strings[0].decode()
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    return None

def check_dkim(domain):
    try:
        message = b"From: example@example.com\r\nTo: example@example.com\r\nSubject: Test\r\n\r\nSample message"  # Example message for DKIM verification
        result = dkim.verify(message)
        return result
    except dkim.ValidationError:
        return None

def check_domain(domain):
    spf_record = check_spf(domain)
    dmarc_record = check_dmarc(domain)
    dkim_result = check_dkim(domain)

    result = []

    if spf_record:
        result.append(Fore.YELLOW + "[*] Found SPF record:" + Style.RESET_ALL)
        result.append(f"[*] {spf_record}")
        if 'all' not in spf_record.lower():
            result.append(Fore.BLUE + "[+] SPF record has no All string" + Style.RESET_ALL)
        
        include_match = re.findall(r'include:([^\s]+)', spf_record)
        if include_match:
            result.append(Fore.YELLOW + "[*] Checking SPF include mechanisms" + Style.RESET_ALL)
            strong_include = True
            for include in include_match:
                include_spf = check_spf(include)
                if not include_spf or 'all' not in include_spf.lower():
                    strong_include = False
                    result.append(f"[-] Include mechanism {include} does not have a strong record")
            if strong_include:
                result.append(Fore.BLUE + "[-] Include mechanisms include strong records" + Style.RESET_ALL)
    else:
        result.append(Fore.GREEN + "[+] No SPF record found" + Style.RESET_ALL)

    if dmarc_record:
        result.append(Fore.YELLOW + "[*] Found DMARC record:" + Style.RESET_ALL)
        result.append(f"[*] {dmarc_record}")
    else:
        result.append(Fore.GREEN + "[+] No DMARC record found" + Style.RESET_ALL)

    if not dkim_result:
        result.append(Fore.GREEN + "[+] No DKIM record found" + Style.RESET_ALL)

    spoofable = not (spf_record and dmarc_record)
    if spoofable:
        result.append(Fore.YELLOW + f"[+] Spoofing possible for {domain}!" + Style.RESET_ALL)
    else:
        result.append(Fore.RED + "[-] Domain is not spoofable" + Style.RESET_ALL)
    
    return '\n'.join(result)



def check_dmarc_policy_level(domain):
    try:
        dmarc_records = dns.resolver.resolve('_dmarc.' + domain, 'TXT')
        for record in dmarc_records:
            if record.strings and b'v=DMARC1' in record.strings[0]:
                policy_level = re.search(r'p=(\w+)', record.strings[0].decode())
                if policy_level:
                    policy_level = policy_level.group(1).lower()
                    if policy_level in ['none', 'quarantine', 'reject']:
                        return policy_level
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    return None

# Example usage
print_banner()
print_greetings()

try:
    while True:
        domain_name = input("Enter the domain name (or 'exit' to quit): ")
        if domain_name.lower() == 'exit':
            break
        
        # Validate the input as a domain name
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain_name):
            print("Invalid domain name. Please try again.")
            continue

        result = check_domain(domain_name)
        print(result)
        print()
except KeyboardInterrupt:
    print("\n\nProgram terminated by the user. Exiting...")

