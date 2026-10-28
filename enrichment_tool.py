import json
import os
import requests
import base64
import argparse
import dotenv
import ipaddress
from datetime import datetime, timezone
from ioc_extractor import ioc_extraction


dotenv.load_dotenv()

VT_API_Key = os.environ.get("VT_API_KEY")
headers = {
    "accept": "application/json",
    "x-apikey": VT_API_Key or "",
}

AbuseIPDB_API_Key = os.environ.get("ABUSEIPDB_API_KEY")
abuse_headers = {
    "Accept": "application/json",
    "Key": AbuseIPDB_API_Key or "",
}


def enrich_hashes(hashes: list) -> dict:
    """Enrich a list of file hashes via VirusTotal v3 API with error handling and consistent output schema."""
    hashes_report = {"hashes": []}

    for file_hash in hashes:
        if not file_hash or not str(file_hash).strip():
            continue

        clean_hash = str(file_hash).strip().lower()
        target_url = f"https://www.virustotal.com/api/v3/files/{clean_hash}"

        # Default record structure
        record = {
            "indicator": clean_hash,
            "provider": "VirusTotal",
            "queried_at": datetime.now(timezone.utc).isoformat(),
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "verdict": "Unknown",
            "limitations": (
                "Zero VT detections do not guarantee safety for newly compiled"
                " or targeted malware."
            ),
        }

        try:
            response = requests.get(target_url, headers=headers, timeout=10)

            if response.status_code == 200:
                payload = response.json()
                if not isinstance(payload, dict):
                    raise ValueError("Invalid JSON response structure")

                data = payload.get("data", {})
                if not isinstance(data, dict):
                    raise ValueError("Invalid 'data' field in VirusTotal response")

                attributes = data.get("attributes", {})
                if not isinstance(attributes, dict):
                    raise ValueError("Invalid 'attributes' field in VirusTotal response")

                stats = attributes.get("last_analysis_stats", {})
                if not isinstance(stats, dict):
                    raise ValueError(
                        "Invalid 'last_analysis_stats' field in VirusTotal response"
                    )

                for stat_val in stats.values():
                    if (
                        isinstance(stat_val, bool)
                        or not isinstance(stat_val, (int, float))
                        or stat_val < 0
                    ):
                        raise ValueError(
                            "Invalid detection count in last_analysis_stats"
                        )

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 0

                # Calculate verdict
                if malicious > 0:
                    verdict = "Flagged Malicious"
                elif suspicious > 0:
                    verdict = "Flagged Suspicious"
                elif total > 0:
                    verdict = "No Detections"
                else:
                    verdict = "No Analysis Available"

                record.update({
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "total_engines": total,
                    "verdict": verdict,
                })

            elif response.status_code == 404:
                record["verdict"] = "Unknown"
                record["limitations"] = (
                    "Hash was not found in VirusTotal database (never submitted"
                    " before)."
                )

            elif response.status_code == 429:
                print(f"[!] Rate limit reached for {clean_hash} (HTTP 429).")
                record["verdict"] = "Error (Rate Limited)"
                record["limitations"] = (
                    "API rate limit exceeded (4 requests/min on public VT key)."
                )

            else:
                print(
                    f"[-] API failure for {clean_hash}: HTTP status"
                    f" {response.status_code}"
                )
                record["verdict"] = f"Error (HTTP {response.status_code})"

        except ValueError as err:
            print(f"[!] Invalid API response for {clean_hash}: {err}")
            record["verdict"] = "Error (Invalid API Response)"

        except requests.exceptions.RequestException as err:
            print(f"[!] Request exception for {clean_hash}: {err}")
            record["verdict"] = "Error (Network Failure)"

        hashes_report["hashes"].append(record)

    return hashes_report


def enrich_domains(domains: list) -> dict:
    """Enrich a list of domains (including defanged variants) via VirusTotal v3 API."""
    domains_report = {"domains": []}

    for domain in domains:
        if not domain or not str(domain).strip():
            continue

        clean_domain = str(domain).strip().lower().replace("[.]", ".")
        # Query VT domain endpoint and parse last_analysis_stats from the response
        target_url = f"https://www.virustotal.com/api/v3/domains/{clean_domain}"

        record = {
            "indicator": clean_domain,
            "provider": "VirusTotal",
            "queried_at": datetime.now(timezone.utc).isoformat(),
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "verdict": "Unknown",
            "limitations": (
                "Newly registered domains may lack threat reputation until"
                " active campaigns are detected."
            ),
        }

        try:
            response = requests.get(target_url, headers=headers, timeout=10)

            if response.status_code == 200:
                payload = response.json()
                if not isinstance(payload, dict):
                    raise ValueError("Invalid JSON response structure")

                data = payload.get("data", {})
                if not isinstance(data, dict):
                    raise ValueError("Invalid 'data' field in VirusTotal response")

                attributes = data.get("attributes", {})
                if not isinstance(attributes, dict):
                    raise ValueError("Invalid 'attributes' field in VirusTotal response")

                stats = attributes.get("last_analysis_stats", {})
                if not isinstance(stats, dict):
                    raise ValueError(
                        "Invalid 'last_analysis_stats' field in VirusTotal response"
                    )

                for stat_val in stats.values():
                    if (
                        isinstance(stat_val, bool)
                        or not isinstance(stat_val, (int, float))
                        or stat_val < 0
                    ):
                        raise ValueError(
                            "Invalid detection count in last_analysis_stats"
                        )

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 0

                # Calculate verdict
                if malicious > 0:
                    verdict = "Flagged Malicious"
                elif suspicious > 0:
                    verdict = "Flagged Suspicious"
                elif total > 0:
                    verdict = "No Detections"
                else:
                    verdict = "No Analysis Available"

                domain_id = data.get("id", clean_domain)
                if domain_id is not None and not isinstance(domain_id, str):
                    raise ValueError("Invalid 'id' field in VirusTotal response")

                record.update({
                    "indicator": domain_id or clean_domain,
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "total_engines": total,
                    "verdict": verdict,
                })

            elif response.status_code == 404:
                record["verdict"] = "Unknown"
                record["limitations"] = (
                    "Domain was not found in VirusTotal database (never submitted"
                    " before)."
                )

            elif response.status_code == 429:
                print(f"[!] Rate limit reached for {clean_domain} (HTTP 429).")
                record["verdict"] = "Error (Rate Limited)"
                record["limitations"] = (
                    "API rate limit exceeded (4 requests/min on public VT key)."
                )

            else:
                print(
                    f"[-] API failure for {clean_domain}: HTTP status"
                    f" {response.status_code}"
                )
                record["verdict"] = f"Error (HTTP {response.status_code})"

        except ValueError as err:
            print(f"[!] Invalid API response for {clean_domain}: {err}")
            record["verdict"] = "Error (Invalid API Response)"

        except requests.exceptions.RequestException as err:
            print(f"[!] Request exception for {clean_domain}: {err}")
            record["verdict"] = "Error (Network Failure)"

        domains_report["domains"].append(record)

    return domains_report


def enrich_urls(urls: list) -> dict:
    """Enrich a list of URLs (including defanged variants) via VirusTotal v3 API."""
    urls_report = {"urls": []}

    for url in urls:
        if not url or not str(url).strip():
            continue

        # Defang reversal: restore raw URL, then base64url-encode (without padding) for VT URL lookup
        clean_url = (
            str(url).strip()
            .replace("[.]", ".")
            .replace("[@]", "@")
            .replace("hxxps://", "https://")
            .replace("hxxp://", "http://")
            .replace("s[.]ftp://", "sftp://")
            .replace("f[.]tps://", "ftps://")
            .replace("f[.]tp://", "ftp://")
        )
        encoded_url = base64.urlsafe_b64encode(clean_url.encode()).decode().strip("=")
        target_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"

        record = {
            "indicator": clean_url,
            "provider": "VirusTotal",
            "queried_at": datetime.now(timezone.utc).isoformat(),
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "verdict": "Unknown",
            "limitations": (
                "Newly registered URLs may lack threat reputation until"
                " active campaigns are detected."
            ),
        }

        try:
            response = requests.get(target_url, headers=headers, timeout=10)

            if response.status_code == 200:
                payload = response.json()
                if not isinstance(payload, dict):
                    raise ValueError("Invalid JSON response structure")

                data = payload.get("data", {})
                if not isinstance(data, dict):
                    raise ValueError("Invalid 'data' field in VirusTotal response")

                attributes = data.get("attributes", {})
                if not isinstance(attributes, dict):
                    raise ValueError("Invalid 'attributes' field in VirusTotal response")

                stats = attributes.get("last_analysis_stats", {})
                if not isinstance(stats, dict):
                    raise ValueError(
                        "Invalid 'last_analysis_stats' field in VirusTotal response"
                    )

                for stat_val in stats.values():
                    if (
                        isinstance(stat_val, bool)
                        or not isinstance(stat_val, (int, float))
                        or stat_val < 0
                    ):
                        raise ValueError(
                            "Invalid detection count in last_analysis_stats"
                        )

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 0

                # Calculate verdict
                if malicious > 0:
                    verdict = "Flagged Malicious"
                elif suspicious > 0:
                    verdict = "Flagged Suspicious"
                elif total > 0:
                    verdict = "No Detections"
                else:
                    verdict = "No Analysis Available"

                url_id = data.get("url", clean_url)
                if url_id is not None and not isinstance(url_id, str):
                    raise ValueError("Invalid 'url' field in VirusTotal response")

                record.update({
                    "indicator": url_id or clean_url,
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "total_engines": total,
                    "verdict": verdict,
                })

            elif response.status_code == 404:
                record["verdict"] = "Unknown"
                record["limitations"] = (
                    "URL was not found in VirusTotal database (never submitted"
                    " before)."
                )

            elif response.status_code == 429:
                print(f"[!] Rate limit reached for {clean_url} (HTTP 429).")
                record["verdict"] = "Error (Rate Limited)"
                record["limitations"] = (
                    "API rate limit exceeded (4 requests/min on public VT key)."
                )

            else:
                print(
                    f"[-] API failure for {clean_url}: HTTP status"
                    f" {response.status_code}"
                )
                record["verdict"] = f"Error (HTTP {response.status_code})"

        except ValueError as err:
            print(f"[!] Invalid API response for {clean_url}: {err}")
            record["verdict"] = "Error (Invalid API Response)"

        except requests.exceptions.RequestException as err:
            print(f"[!] Request exception for {clean_url}: {err}")
            record["verdict"] = "Error (Network Failure)"

        urls_report["urls"].append(record)

    return urls_report


def is_private_ip(ip_address):
    """Return True if the string is a valid private, loopback, or link-local IP address."""
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False  # Not a valid IP address syntax


def enrich_ips(ips):
    """Enrich a list of IP addresses via AbuseIPDB v2 API.

    Skips private/loopback/link-local IPs, returning an internal baseline without an API call.
    """
    ips_report = {"ip_addresses": []}

    for ip_address in ips:
        if not ip_address or not str(ip_address).strip():
            continue

        clean_ip = str(ip_address).strip().replace("[.]", ".").replace("[:]", ":")
        if is_private_ip(clean_ip):
            record = {
                "indicator": clean_ip,
                "provider": "N/A (Private IP)",
                "queried_at": datetime.now(timezone.utc).isoformat(),
                "abuse_confidence_score": 0,
                "country_code": "Internal",
                "isp": "Private / Internal Network",
                "domain": "N/A",
                "usage_type": "Private IP (RFC 1918 / Loopback)",
                "total_reports": 0,
                "is_whitelisted": True,
                "verdict": "Internal / Non-Routable",
                "limitations": (
                    "Private and loopback IP addresses cannot be queried"
                    " against public threat intelligence providers."
                ),
            }
            ips_report["ip_addresses"].append(record)
            continue

        # Query AbuseIPDB v2 check endpoint for 90-day community abuse telemetry
        querystring = {
            "ipAddress": clean_ip,
            "maxAgeInDays": "90",
        }
        target_url = "https://api.abuseipdb.com/api/v2/check"
        record = {
            "indicator": clean_ip,
            "provider": "AbuseIPDB",
            "queried_at": datetime.now(timezone.utc).isoformat(),
            "abuse_confidence_score": 0,
            "country_code": "Unknown",
            "isp": "Unknown",
            "domain": "Unknown",
            "usage_type": "Unknown",
            "total_reports": 0,
            "is_whitelisted": False,
            "verdict": "Unknown",
            "limitations": (
                "AbuseIPDB metrics reflect community-reported activity over the"
                " last 90 days."
            ),
        }

        try:
            response = requests.get(
                target_url, headers=abuse_headers, params=querystring, timeout=10
            )
            if response.status_code == 200:
                payload = response.json()
                if not isinstance(payload, dict):
                    raise ValueError("Invalid JSON response structure")

                data = payload.get("data", {})
                if not isinstance(data, dict):
                    raise ValueError("Invalid 'data' field in AbuseIPDB response")

                confidence_score = data.get("abuseConfidenceScore")
                if confidence_score is None:
                    verdict = "Unknown"
                    confidence_score = 0
                elif (
                    isinstance(confidence_score, bool)
                    or not isinstance(confidence_score, (int, float))
                    or confidence_score < 0
                    or confidence_score > 100
                ):
                    raise ValueError(
                        "Invalid abuseConfidenceScore in AbuseIPDB response"
                    )
                elif confidence_score >= 50:
                    verdict = "High Reported Abuse"
                elif confidence_score >= 20:
                    verdict = "Moderate Reported Abuse"
                else:
                    verdict = "Low Reported Abuse"

                record.update({
                    "abuse_confidence_score": confidence_score,
                    "country_code": data.get("countryCode") or "N/A",
                    "isp": data.get("isp") or "N/A",
                    "domain": data.get("domain") or "N/A",
                    "usage_type": data.get("usageType") or "N/A",
                    "total_reports": data.get("totalReports") or 0,
                    "is_whitelisted": bool(data.get("isWhitelisted", False)),
                    "verdict": verdict,
                })

            elif response.status_code == 429:
                print(f"[!] Rate limit reached for IP {clean_ip} (HTTP 429).")
                record["verdict"] = "Error (Rate Limited)"

            else:
                print(
                    f"[-] AbuseIPDB failure for {clean_ip}: HTTP status"
                    f" {response.status_code}"
                )
                record["verdict"] = f"Error (HTTP {response.status_code})"

        except ValueError as err:
            print(f"[!] Invalid API response for {clean_ip}: {err}")
            record["verdict"] = "Error (Invalid API Response)"

        except requests.exceptions.RequestException as err:
            print(f"[!] Request exception for {clean_ip}: {err}")
            record["verdict"] = "Error (Network Failure)"

        ips_report["ip_addresses"].append(record)

    return ips_report


def main():
    ioc_type = ["ip_addresses", "urls", "domains", "emails", "hashes"]
    ips = []
    urls = []
    domains = []
    emails = []
    hashes = []

    parser = argparse.ArgumentParser(
        description="Enrich extracted IOCs using VirusTotal and AbuseIPDB."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--input", help="Path to input file")
    group.add_argument("-s", "--single", help="Single Indicator Mode")
    parser.add_argument(
        "-t",
        "--type",
        choices=["ip", "domain", "hash", "url"],
        help="Indicator type (only with --single)",
    )
    parser.add_argument("-o", "--output", required=True, help="Path to output file")
    args = parser.parse_args()

    if args.single and not args.type:
        parser.error("--single requires --type")

    if not VT_API_Key:
        print("Missing VirusTotal API key.")
        exit(1)

    if not AbuseIPDB_API_Key:
        print("Missing AbuseIPDB API key.")
        exit(1)

    input_file = args.input
    input_indicator = args.single
    indicator_type = args.type
    output_file = args.output

    if input_indicator:
        clean_indicator = input_indicator.strip()
        if indicator_type == "ip":
            clean_indicator = clean_indicator.replace("[.]", ".").replace("[:]", ":")
        elif indicator_type == "domain":
            clean_indicator = clean_indicator.replace("[.]", ".").lower()
        elif indicator_type == "url":
            clean_indicator = (
                clean_indicator.replace("[.]", ".")
                .replace("[@]", "@")
                .replace("hxxps://", "https://")
                .replace("hxxp://", "http://")
                .replace("s[.]ftp://", "sftp://")
                .replace("f[.]tps://", "ftps://")
                .replace("f[.]tp://", "ftp://")
            )
        elif indicator_type == "hash":
            clean_indicator = clean_indicator.lower()

        raw_ips, raw_emails, raw_urls, raw_domains, raw_hashes = ioc_extraction(
            clean_indicator
        )

        extracted = {
            "ip": raw_ips,
            "domain": raw_domains,
            "url": raw_urls,
            "hash": raw_hashes,
        }

        if (
            len(extracted[indicator_type]) != 1
            or extracted[indicator_type][0] != clean_indicator
        ):
            parser.error(f"Invalid {indicator_type} indicator: {input_indicator}")

    if input_file:
        try:
            with open(input_file, "r", encoding="utf-8") as file:
                content = json.load(file)

            # Validate JSON structure
            if not isinstance(content, dict) or not isinstance(content.get("iocs"), dict):
                parser.error("Invalid IOC JSON structure.")

            # Validate IOC categories and entries
            for category in ioc_type:
                entries = content["iocs"].get(category)

                if not isinstance(entries, list):
                    parser.error(f"Missing or invalid IOC category: {category}")

                expected_key = "value" if category == "hashes" else "raw"

                for entry in entries:
                    if (
                        not isinstance(entry, dict)
                        or not isinstance(entry.get(expected_key), str)
                    ):
                        parser.error(f"Invalid entry in {category}")

                    raw_val = entry[expected_key].strip()
                    if not raw_val:
                        parser.error(
                            f"Invalid {category} indicator: {entry[expected_key]}"
                        )

                    if category == "ip_addresses":
                        clean_val = raw_val.replace("[.]", ".").replace("[:]", ":")
                        ext_ips, _, _, _, _ = ioc_extraction(clean_val)
                        if len(ext_ips) != 1 or ext_ips[0] != clean_val:
                            parser.error(
                                f"Invalid {category} indicator: {entry[expected_key]}"
                            )

                    elif category == "urls":
                        clean_val = (
                            raw_val.replace("[.]", ".")
                            .replace("[@]", "@")
                            .replace("hxxps://", "https://")
                            .replace("hxxp://", "http://")
                            .replace("s[.]ftp://", "sftp://")
                            .replace("f[.]tps://", "ftps://")
                            .replace("f[.]tp://", "ftp://")
                        )
                        _, _, ext_urls, _, _ = ioc_extraction(clean_val)
                        if len(ext_urls) != 1 or ext_urls[0] != clean_val:
                            parser.error(
                                f"Invalid {category} indicator: {entry[expected_key]}"
                            )

                    elif category == "domains":
                        clean_val = raw_val.replace("[.]", ".").lower()
                        _, _, _, ext_domains, _ = ioc_extraction(clean_val)
                        if len(ext_domains) != 1 or ext_domains[0] != clean_val:
                            parser.error(
                                f"Invalid {category} indicator: {entry[expected_key]}"
                            )

                    elif category == "emails":
                        clean_val = raw_val.replace("[@]", "@").replace("[.]", ".")
                        if "@" in clean_val:
                            local_part, domain_part = clean_val.split("@", 1)
                            clean_val = f"{local_part}@{domain_part.lower()}"
                        else:
                            domain_part = ""
                        _, ext_emails, _, _, _ = ioc_extraction(clean_val)
                        _, _, _, ext_email_domains, _ = ioc_extraction(
                            domain_part.lower()
                        )
                        if (
                            len(ext_emails) != 1
                            or ext_emails[0] != clean_val
                            or len(ext_email_domains) != 1
                            or ext_email_domains[0] != domain_part.lower()
                        ):
                            parser.error(
                                f"Invalid {category} indicator: {entry[expected_key]}"
                            )

                    elif category == "hashes":
                        clean_val = raw_val.lower()
                        _, _, _, _, ext_hashes = ioc_extraction(clean_val)
                        if len(ext_hashes) != 1 or ext_hashes[0] != clean_val:
                            parser.error(
                                f"Invalid {category} indicator: {entry[expected_key]}"
                            )

        except (OSError, UnicodeError, json.JSONDecodeError) as err:
            parser.error(f"Unable to read IOC JSON: {err}")

        # Extract indicators from validated JSON
        for category in ioc_type:
            for i in range(len(content["iocs"][category])):
                if category == "ip_addresses":
                    ips.append(content["iocs"][category][i]["raw"])
                elif category == "urls":
                    urls.append(content["iocs"][category][i]["raw"])
                elif category == "domains":
                    domains.append(content["iocs"][category][i]["raw"])
                elif category == "emails":
                    emails.append(content["iocs"][category][i]["raw"])
                elif category == "hashes":
                    hashes.append(content["iocs"][category][i]["value"])

        # Extract domains from email addresses safely
        emails_domains = []
        for email in emails:
            clean_email = email.strip().replace("[@]", "@").replace("[.]", ".")
            if "@" in clean_email:
                email_domain = clean_email.split("@", 1)[1].strip().lower()
                if email_domain:
                    emails_domains.append(email_domain)

        # Deduplicate domains deterministically while normalizing case and defanging
        normalized_domains = [
            d.strip().lower().replace("[.]", ".")
            for d in domains
            if d and d.strip()
        ]
        all_domains = list(dict.fromkeys(normalized_domains + emails_domains))

        # Enrich extracted indicators
        ips_report = enrich_ips(ips)
        urls_report = enrich_urls(urls)
        domains_report = enrich_domains(all_domains)
        hashes_report = enrich_hashes(hashes)

        # Generate report metadata
        metadata = {
            "metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_indicators_processed": (
                    len(ips_report["ip_addresses"])
                    + len(urls_report["urls"])
                    + len(domains_report["domains"])
                    + len(hashes_report["hashes"])
                ),
                "providers_queried": ["VirusTotal", "AbuseIPDB"],
            }
        }

        # Combine enrichment results
        full_report = {
            **metadata,
            "enriched_iocs": {
                **ips_report,
                **urls_report,
                **domains_report,
                **hashes_report,
            },
        }

    elif input_indicator:
        if indicator_type == "ip":
            ip_report = enrich_ips([input_indicator])
            full_report = {**ip_report}
        elif indicator_type == "domain":
            domain_report = enrich_domains([input_indicator])
            full_report = {**domain_report}
        elif indicator_type == "hash":
            hash_report = enrich_hashes([input_indicator])
            full_report = {**hash_report}
        elif indicator_type == "url":
            url_report = enrich_urls([input_indicator])
            full_report = {**url_report}

    try:
        with open(output_file, "w", encoding="utf-8") as output:
            json.dump(full_report, output, indent=4)
    except OSError as err:
        parser.error(f"Unable to write output file: {err}")


if __name__ == "__main__":
    main()