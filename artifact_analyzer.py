import pyperclip, sys, requests, re, os
from dotenv import load_dotenv
import ipaddress


def ip_extraction(text):
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    potential_ips = ip_re.findall(text)

    valid_ips = []

    for ip in potential_ips:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_global:
                valid_ips.append(str(ip_obj))
        except ValueError:
            continue
    return valid_ips


def domain_extraction(text):
    domain_re = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
    valid_domains = domain_re.findall(text)
    return valid_domains


def hash_extraction(text):
    md5_re = re.compile(r"\b[A-Fa-f0-9]{32}\b")
    sha1_re = re.compile(r"\b[A-Fa-f0-9]{40}\b")
    sha256_re = re.compile(r"\b[A-Fa-f0-9]{64}\b")

    hash_list = md5_re.findall(text) + (sha1_re.findall(text)) + sha256_re.findall(text)
    return hash_list


def get_vt_url(artifact):
    try:
        ipaddress.ip_address(artifact)
        return f"https://www.virustotal.com/api/v3/ip_addresses/{artifact}"
    except ValueError:
        pass

    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", artifact):
        return f"https://www.virustotal.com/api/v3/files/{artifact}"

    if re.fullmatch(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", artifact):
        return f"https://www.virustotal.com/api/v3/domains/{artifact}"

    # If it matches none of the above
    raise ValueError(f"Unrecognized artifact format: {artifact}")


# query the TI platforms
def query_vt(artifact):
    vt_api = os.getenv("VIRUSTOTAL_API")

    if not vt_api:
        raise ValueError("VirusTotal's API is not configured!")
    # vt query
    vt_url = get_vt_url(artifact)
    vt_headers = {"x-apikey": vt_api}
    vt_response = requests.get(vt_url, headers=vt_headers, timeout=10)

    response = vt_response.json()
    attributes = response["data"]["attributes"]
    network = attributes.get("network")

    result = {
        "artifact": response["data"]["id"],
        "network": attributes.get("network"),
        "asn": attributes.get("asn"),
        "as_owner": attributes.get("as_owner"),
        "country": attributes.get("country"),
        "reputation": attributes.get("reputation"),
        "analysis_stats": attributes.get("last_analysis_stats"),
    }
    return result


def query_abuse(artifact):
    abuse_api = os.getenv("ABUSEIPDB_API")
    if not abuse_api:
        raise ValueError("AbuseIPDB's API is not configured!")
    # abuseipdb query
    abuse_url = "https://api.abuseipdb.com/api/v2/check"
    abuse_headers = {"Accept": "application/json", "Key": abuse_api}
    querystring = {"ipAddress": artifact, "maxAgeInDays": "90"}
    abuse_response = requests.get(
        abuse_url, headers=abuse_headers, params=querystring, timeout=10
    )

    return abuse_response.json()


if __name__ == "__main__":
    load_dotenv()
    text = str(pyperclip.paste())
    domains = domain_extraction(text)
    hashes = hash_extraction(text)
    ips = ip_extraction(text)
    print(query_vt("200.40.115.238"))
