import re
import argparse
import json
from urllib.parse import urlsplit
from ipaddress import ip_address


# Regex patterns
ipv4_regex = r"(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d)(?!\.\d)"
ipv6_regex = r"(?<![:\w])(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:))(?![:\w])"
octet = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
ipv4_mapped_regex = rf"(?<![\w:.])::[fF]{{4}}:(?:{octet}\.){{3}}{octet}(?![\w:.])"

domain_regex = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,63}|xn--[a-zA-Z0-9-]{1,59})\b"
email_regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b"
url_regex = r"\b(?:https?|ftps?|sftp)://(?:[^\s/?#@]+@)?(?:\[[0-9a-fA-F:.]+\]|localhost|(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59})|(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))(?::\d{1,5})?(?:[/?#](?:[^\s<>\"'`]*[^\s<>\"'`.,;:!?)\]}])?)?"

# Hash patterns
md5_regex = r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])"
sha1_regex = r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])"
sha224_regex = r"(?<![a-fA-F0-9])[a-fA-F0-9]{56}(?![a-fA-F0-9])"
sha256_regex = r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])"
sha384_regex = r"(?<![a-fA-F0-9])[a-fA-F0-9]{96}(?![a-fA-F0-9])"
sha512_regex = r"(?<![a-fA-F0-9])[a-fA-F0-9]{128}(?![a-fA-F0-9])"


def ioc_extraction(file_content):
    """Extract unique IPv4/IPv6 addresses, emails, URLs, domains, and file hashes from text."""
    raw_ips = []
    valid_urls = []

    # Find IP addresses and validate with ipaddress module
    ip_candidates = list(dict.fromkeys(re.findall(
        f"{ipv4_mapped_regex}|{ipv4_regex}|{ipv6_regex}", file_content
    )))

    for ip in ip_candidates:
        try:
            if ip_address(ip):
                raw_ips.append(ip)
        except ValueError:
            continue

    # Find URLs and validate their port numbers
    raw_urls = list(dict.fromkeys(re.findall(url_regex, file_content)))

    for url in raw_urls:
        try:
            parsed = urlsplit(url)
            _ = parsed.port
            valid_urls.append(url)
        except ValueError:
            continue

    raw_urls = valid_urls

    # Find email addresses (preserve local-part case, normalize domain to lowercase)
    raw_emails = list(dict.fromkeys(
        email.split("@")[0] + "@" + email.split("@")[1].lower()
        for email in re.findall(email_regex, file_content)
    ))

    # Extract hostnames from URLs, excluding IP literals and localhost
    url_domains = []

    for url in raw_urls:
        hostname = urlsplit(url).hostname
        if hostname and hostname.lower() != "localhost":
            try:
                ip_address(hostname)
            except ValueError:
                url_domains.append(hostname)

    # Extract domains from email addresses
    email_domains = []

    for email in raw_emails:
        email_domains.append(email.split("@")[1].lower())

    # Mask URLs, emails, and IPs before scanning for standalone domains to avoid false sub-matches
    masked_text = file_content

    for pattern in [url_regex, email_regex, ipv4_mapped_regex, ipv4_regex, ipv6_regex]:
        masked_text = re.sub(
            pattern,
            lambda m: " " * len(m.group()),
            masked_text
        )

    # Find standalone domains
    standalone_domains = re.findall(domain_regex, masked_text)

    # Filter out common file names mistaken for domains
    file_extensions = {
        ".exe", ".pdf", ".zip", ".dll",
        ".ps1", ".png", ".jpg", ".jpeg",
        ".csv", ".docx", ".xlsx", ".bat",
        ".txt", ".log", ".py", ".js",
        ".html", ".css", ".json"
    }

    standalone_domains = [
        domain for domain in standalone_domains
        if "." + domain.rsplit(".", 1)[-1].lower() not in file_extensions
    ]

    # Combine domains and remove duplicates while preserving discovery order
    raw_domains = list(dict.fromkeys(
        domain.lower() for domain in (url_domains + email_domains + standalone_domains)
    ))

    # Find file hashes and remove duplicates
    raw_hashes = list(dict.fromkeys(
        hash_val.lower() for hash_val in re.findall(
            f"{md5_regex}|{sha1_regex}|{sha224_regex}|{sha256_regex}|{sha384_regex}|{sha512_regex}",
            file_content
        )
    ))

    return raw_ips, raw_emails, raw_urls, raw_domains, raw_hashes


def defang(raw_iocs, ioc_type, defanged_iocs):
    """Defang a list of raw IOCs in place based on indicator category."""
    for ioc in raw_iocs:
        if ioc_type == "url":
            ioc = (
                ioc.replace(".", "[.]")
                .replace("https://", "hxxps://")
                .replace("http://", "hxxp://")
                .replace("ftps://", "f[.]tps://")
                .replace("ftp://", "f[.]tp://")
                .replace("sf[.]tp://", "s[.]ftp://")
                .replace("@", "[@]")
            )

        elif ioc_type == "email":
            ioc = ioc.replace("@", "[@]").replace(".", "[.]")

        elif ioc_type == "domain":
            ioc = ioc.replace(".", "[.]")

        elif ioc_type == "ip":
            ioc = ioc.replace(".", "[.]").replace(":", "[:]")

        defanged_iocs.append(ioc)


def main():
    # CLI arguments
    parser = argparse.ArgumentParser(
        description="Extract and defang IOCs from text or files."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Path to input file")
    group.add_argument("-t", "--text", help="Raw text string input")
    parser.add_argument("-o", "--output", required=False, help="Path to output file")

    args = parser.parse_args()
    input_text = args.text
    input_file = args.file
    output_file = args.output

    defanged_ips = []
    defanged_domains = []
    defanged_emails = []
    defanged_urls = []

    # Read input from a file or direct text
    if input_file:
        try:
            with open(input_file, "r", encoding="utf-8", errors="ignore") as file:
                content = file.read()
        except OSError as err:
            parser.error(f"Unable to read input file: {err}")
    else:
        content = input_text

    # Extract IOCs
    raw_ips, raw_emails, raw_urls, raw_domains, raw_hashes = ioc_extraction(content)

    # Defang extracted IOCs
    defang(raw_ips, "ip", defanged_ips)
    defang(raw_urls, "url", defanged_urls)
    defang(raw_emails, "email", defanged_emails)
    defang(raw_domains, "domain", defanged_domains)

    # Print formatted report to stdout if no output file is specified
    if not output_file:
        print("=" * 80)
        print("                           IOC EXTRACTOR REPORT")
        print("=" * 80)

        print(f"IP Addresses ({len(raw_ips)} found):")
        for i in range(len(raw_ips)):
            print(f"- Raw: {raw_ips[i]}     -> Defanged: {defanged_ips[i]}")
        print("")

        print(f"URLs ({len(raw_urls)} found):")
        for i in range(len(raw_urls)):
            print(f"- Raw: {raw_urls[i]}     -> Defanged: {defanged_urls[i]}")
        print("")

        print(f"Domains ({len(raw_domains)} found):")
        for i in range(len(raw_domains)):
            print(f"- Raw: {raw_domains[i]}     -> Defanged: {defanged_domains[i]}")
        print("")

        print(f"Email Addresses ({len(raw_emails)} found):")
        for i in range(len(raw_emails)):
            print(f"- Raw: {raw_emails[i]}     -> Defanged: {defanged_emails[i]}")
        print("")

        print(f"File Hashes ({len(raw_hashes)} found):")
        for i in range(len(raw_hashes)):
            print(f"- Raw: {raw_hashes[i]}")

    # Export results as JSON
    else:
        try:
            with open(output_file, "w", encoding="utf-8") as output:
                data = {
                    "summary": {
                        "ip_count": len(raw_ips),
                        "url_count": len(raw_urls),
                        "domain_count": len(raw_domains),
                        "email_count": len(raw_emails),
                        "hash_count": len(raw_hashes),
                    },
                    "iocs": {
                        "ip_addresses": [
                            {"raw": r, "defanged": d}
                            for r, d in zip(raw_ips, defanged_ips)
                        ],
                        "urls": [
                            {"raw": r, "defanged": d}
                            for r, d in zip(raw_urls, defanged_urls)
                        ],
                        "domains": [
                            {"raw": r, "defanged": d}
                            for r, d in zip(raw_domains, defanged_domains)
                        ],
                        "emails": [
                            {"raw": r, "defanged": d}
                            for r, d in zip(raw_emails, defanged_emails)
                        ],
                        "hashes": [
                            {
                                "type": (
                                    "MD5" if len(v) == 32 else
                                    "SHA-1" if len(v) == 40 else
                                    "SHA-256" if len(v) == 64 else
                                    "SHA-512" if len(v) == 128 else
                                    "SHA-384" if len(v) == 96 else
                                    "SHA-224" if len(v) == 56 else
                                    "Unknown"
                                ),
                                "value": v
                            }
                            for v in raw_hashes
                        ]
                    }
                }

                json.dump(data, output, indent=4)
        except OSError as err:
            parser.error(f"Unable to write output file: {err}")


if __name__ == "__main__":
    main()
