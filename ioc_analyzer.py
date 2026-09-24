import pyperclip, sys, requests, re, os
from dotenv import load_dotenv
from datetime import datetime, timezone
import ipaddress
from urllib.parse import urlsplit


COLORS = {
    "heading": "1;36", "title": "1;35", "danger": "1;31",
    "warning": "33", "zero": "32", "muted": "90",
}


def color_text(value, color, stream=None):
    stream = sys.stdout if stream is None else stream
    text = str(value)
    if "NO_COLOR" in os.environ or not stream.isatty():
        return text
    if os.name == "nt":
        # Enable ANSI escapes on Windows consoles; fall back to plain text.
        import ctypes
        import msvcrt
        try:
            handle = ctypes.c_void_p(msvcrt.get_osfhandle(stream.fileno()))
            mode = ctypes.c_ulong()
            kernel = ctypes.windll.kernel32
            if not kernel.GetConsoleMode(handle, ctypes.byref(mode)):
                return text
            if not kernel.SetConsoleMode(handle, mode.value | 0x0004):
                return text
        except (OSError, ValueError, AttributeError):
            return text
    return f"\033[{COLORS[color]}m{text}\033[0m"


def print_section(title):
    print(color_text(f"\n[ {title} ]", "heading"))


def print_error(message):
    print(color_text(message, "danger", sys.stderr), file=sys.stderr)


def print_vt_stats(vt):
    print_section("VirusTotal")
    if vt is None:
        print(color_text("Unavailable", "warning"))
        return
    for label, key in (("Malicious", "malicious"), ("Suspicious", "suspicious")):
        count = vt[key]
        value = f"{count} / {vt['total']}" if count is not None else "Unavailable"
        tone = "warning" if count is None else "zero" if count == 0 else (
            "danger" if key == "malicious" else "warning")
        print(f"{label:<14}: {color_text(value, tone)}")
    reputation = vt['reputation']
    tone = "warning" if reputation is None else "danger" if reputation < 0 else "muted"
    print(f"Reputation     : {color_text(reputation, tone)}")


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
    domains = []

    def extract_host(match):
        try:
            url = match.group().rstrip(".,;!?)")
            if not url.startswith("//") and "://" not in url:
                url = "//" + url
            host = urlsplit(url).hostname
            if host and is_domain(host):
                domains.append(host.lower())
        except ValueError:
            pass
        return " "

    # Consume entire URLs so paths and query strings cannot become domains.
    remaining = re.sub(r"(?:[a-zA-Z][a-zA-Z0-9+.-]*://|//)[^\s<>\"']+",
                       extract_host, text)
    remaining = re.sub(r"(?<![\w.-])(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}"
                       r"(?::\d+)?[/?#][^\s<>\"']*", extract_host, remaining)
    for candidate in re.findall(r"[a-zA-Z0-9_.-]+", remaining):
        candidate = candidate.rstrip(".")
        if is_domain(candidate):
            domains.append(candidate.lower())
    return list(dict.fromkeys(domains))


def is_domain(value):
    label = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    return len(value) <= 253 and re.fullmatch(
        rf"(?:{label}\.)+[a-zA-Z]{{2,63}}", value
    ) is not None


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

    if is_domain(artifact):
        return f"https://www.virustotal.com/api/v3/domains/{artifact}"

    # If it matches none of the above
    raise ValueError(f"Unrecognized artifact format: {artifact}")

def get_json(url, headers, params=None):
    response = requests.get(url=url, headers=headers, params=params, timeout=10)
    response.raise_for_status()
    return response.json()

def format_timestamp(timestamp):
    if not timestamp:
        return None

    return datetime.fromtimestamp(
        timestamp,
        tz=timezone.utc
    ).strftime("%Y-%m-%d %H:%M UTC")

def parse_vt_ip(response):
    attributes = response["data"]["attributes"]

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

def parse_vt_domain(response):
    data = response["data"]
    attributes = data["attributes"]

    stats = attributes.get("last_analysis_stats", {})

    return {
        "artifact": data["id"],
        "type": "domain",

        "analysis_stats": stats,
        "reputation": attributes.get("reputation"),
        "total_votes": attributes.get("total_votes"),
        "categories": attributes.get("categories"),

        "registrar": attributes.get("registrar"),
        "tld": attributes.get("tld"),
        "creation_date": attributes.get("creation_date"),
        "expiration_date": attributes.get("expiration_date"),

        "first_seen_date": attributes.get("first_seen_date"),
        "last_analysis_date": attributes.get("last_analysis_date"),

        "dns_records": attributes.get("last_dns_records"),
        "dns_records_date": attributes.get("last_dns_records_date"),

        "tags": attributes.get("tags"),
    }

def parse_vt_file(response):
    data = response["data"]
    attributes = data["attributes"]

    return {
        "artifact": data["id"],
        "type": "file",

        "analysis_stats": attributes.get("last_analysis_stats"),
        "reputation": attributes.get("reputation"),

        "meaningful_name": attributes.get("meaningful_name"),
        "names": attributes.get("names"),

        "type_description": attributes.get("type_description"),
        "type_extension": attributes.get("type_extension"),
        "size": attributes.get("size"),

        "md5": attributes.get("md5"),
        "sha1": attributes.get("sha1"),
        "sha256": attributes.get("sha256"),

        "first_submission_date": attributes.get("first_submission_date"),
        "last_submission_date": attributes.get("last_submission_date"),
        "last_analysis_date": attributes.get("last_analysis_date"),

        "tags": attributes.get("tags"),

        "threat_classification": attributes.get(
            "popular_threat_classification"
        ),

        "sandbox_verdicts": attributes.get("sandbox_verdicts"),
    }
# query the TI platforms
def query_vt(artifact):
    vt_api = os.getenv("VIRUSTOTAL_API")

    if not vt_api:
        raise ValueError("VirusTotal's API is not configured!")
    # vt query
    vt_url = get_vt_url(artifact)
    vt_headers = {"x-apikey": vt_api}
    response = get_json(vt_url, vt_headers)

    artifact_type = response['data']['type']
    if artifact_type == "ip_address":
        return parse_vt_ip(response)
    elif artifact_type == "domain":
        return parse_vt_domain(response)
    elif artifact_type == "file":
        return parse_vt_file(response)
    else:
        raise ValueError(f"Unsupported VT type: {artifact_type}")



def query_abuse(artifact):
    abuse_api = os.getenv("ABUSEIPDB_API")
    if not abuse_api:
        raise ValueError("AbuseIPDB's API is not configured!")
    # abuseipdb query
    abuse_url = "https://api.abuseipdb.com/api/v2/check"
    abuse_headers = {"Accept": "application/json", "Key": abuse_api}
    querystring = {"ipAddress": artifact, "maxAgeInDays": "90"}
    response = get_json(url=abuse_url, headers=abuse_headers, params=querystring)

    data = response["data"]
    result = {
        "artifact": data.get("ipAddress"),
        "source": "AbuseIPDB",
        "abuse_confidence": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "distinct_reporters": data.get("numDistinctUsers"),
        "last_reported_at": data.get("lastReportedAt"),
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "usage_type": data.get("usageType"),
        "domain": data.get("domain"),
        "hostnames": data.get("hostnames"),
        "is_tor": data.get("isTor"),

    }
    return result

#normalization
def normalize_ip_result(vt_result, abuse_result, indicator=None):
    vt_result = vt_result or {}
    abuse_result = abuse_result or {}
    vt_stats = vt_result.get("analysis_stats") or {}

    total = sum(vt_stats.values()) if vt_stats else None
    result = {
        "indicator": indicator or vt_result.get("artifact") or abuse_result.get("artifact"),
        "type": "ip",

        "virustotal": {
            "malicious": vt_stats.get('malicious'),
            "suspicious": vt_stats.get('suspicious'),
            "total": total,
            "reputation": vt_result.get("reputation"),
        } if vt_result else None,

        "abuseipdb": {
            "confidence": abuse_result.get('abuse_confidence'),
            "total_reports": abuse_result.get('total_reports'),
            "distinct_reporters": abuse_result.get("distinct_reporters"),
            "last_reported": abuse_result.get("last_reported_at")
        } if abuse_result else None,

        "network_context": {
            "country": vt_result.get('country') or abuse_result.get('country'),
            "asn": vt_result.get('asn'),
            "owner": vt_result.get('as_owner') or abuse_result.get('isp'),
            "network": vt_result.get('network'),
            "usage_type": abuse_result.get('usage_type'),
            "domain": abuse_result.get('domain'),
            "is_tor": abuse_result.get('is_tor')
        }
    }

    return result

def normalize_domain_result(vt_result):
    stats = vt_result["analysis_stats"] or {}
    total = sum(stats.values())

    dns_records = []

    for record in vt_result.get("dns_records") or []:
        dns_records.append({
            "type": record.get("type"),
            "value": record.get("value")
        })

    return {
        "indicator": vt_result["artifact"],
        "type": "domain",

        "virustotal": {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "total": total,
            "reputation": vt_result.get("reputation"),
        },

        "domain_context": {
            "registrar": vt_result.get("registrar"),
            "tld": vt_result.get("tld"),
            "creation_date": format_timestamp(
                vt_result.get("creation_date")
            ),
            "expiration_date": format_timestamp(
                vt_result.get("expiration_date")
            ),
            "first_seen": format_timestamp(
                vt_result.get("first_seen_date")
            ),
        },

        "dns": {
            "records": dns_records
        },

        "tags": vt_result.get("tags") or []
    }

def normalize_file_result(vt_result):
    stats = vt_result["analysis_stats"] or {}
    total = sum(stats.values())

    classification = vt_result.get("threat_classification") or {}

    sandbox_verdicts = {}

    for sandbox, verdict in (
        vt_result.get("sandbox_verdicts") or {}
    ).items():
        sandbox_verdicts[sandbox] = verdict.get("category")

    return {
        "indicator": vt_result["artifact"],
        "type": "file",

        "virustotal": {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "total": total,
            "reputation": vt_result.get("reputation"),
            "threat_label": classification.get(
                "suggested_threat_label"
            ),
        },

        "file_context": {
            "name": vt_result.get("meaningful_name"),
            "type": vt_result.get("type_description"),
            "extension": vt_result.get("type_extension"),
            "size": vt_result.get("size"),

            "md5": vt_result.get("md5"),
            "sha1": vt_result.get("sha1"),
            "sha256": vt_result.get("sha256"),

            "tags": vt_result.get("tags") or []
        },

        "timeline": {
            "first_submission": format_timestamp(
                vt_result.get("first_submission_date")
            ),
            "last_submission": format_timestamp(
                vt_result.get("last_submission_date")
            ),
            "last_analysis": format_timestamp(
                vt_result.get("last_analysis_date")
            )
        },

        "sandbox": sandbox_verdicts
    }


#print dispatcher
def print_analysis(result):
    print(color_text("=" * 70, "muted"))
    print(color_text(f"IOC ANALYSIS: {result['indicator']}", "title"))
    print(color_text(f"TYPE: {result['type'].upper()}", "heading"))
    print(color_text("=" * 70, "muted"))

    if result["type"] == "ip":
        print_ip_result(result)

    elif result["type"] == "domain":
        print_domain_result(result)

    elif result["type"] == "file":
        print_file_result(result)

    else:
        print("Unsupported IOC type.")

    print(color_text("=" * 70, "muted"))

def print_ip_result(result):
    vt = result["virustotal"]
    abuse = result["abuseipdb"]
    context = result["network_context"]

    print_vt_stats(vt)

    print_section("AbuseIPDB")
    if abuse is None:
        print(color_text("Unavailable", "warning"))
    else:
        confidence = abuse['confidence']
        tone = "zero" if confidence == 0 else "warning"
        value = "Unavailable" if confidence is None else f"{confidence}%"
        print(f"Confidence     : {color_text(value, tone)}")
        print(f"Reports        : {abuse['total_reports']}")
        print(f"Reporters      : {abuse['distinct_reporters']}")
        print(f"Last reported  : {abuse['last_reported']}")

    print_section("Network Context")
    print(f"Country        : {context['country']}")
    print(f"ASN            : AS{context['asn']}")
    print(f"Owner          : {context['owner']}")
    print(f"Network        : {context['network']}")
    print(f"Usage          : {context['usage_type']}")
    print(f"Domain         : {context['domain']}")
    print(
        f"Tor            : "
        f"{'Unavailable' if context['is_tor'] is None else 'Yes' if context['is_tor'] else 'No'}"
    )

def print_domain_result(result):
    vt = result["virustotal"]
    context = result["domain_context"]
    dns = result["dns"]

    print_vt_stats(vt)

    print_section("Domain Context")
    print(f"Registrar      : {context['registrar']}")
    print(f"TLD            : {context['tld']}")
    print(f"Created        : {context['creation_date']}")
    print(f"Expires        : {context['expiration_date']}")
    print(f"First Seen     : {context['first_seen']}")

    print_section("DNS Records")

    if dns["records"]:
        for record in dns["records"]:
            print(
                f"{record['type']:<14}: "
                f"{record['value']}"
            )
    else:
        print(color_text("No DNS records available", "muted"))

    if result["tags"]:
        print(f"\nTags           : {', '.join(result['tags'])}")

def print_file_result(result):
    vt = result["virustotal"]
    context = result["file_context"]
    timeline = result["timeline"]

    print_vt_stats(vt)
    print(f"Threat Label   : {color_text(vt['threat_label'], 'warning' if vt['threat_label'] else 'muted')}")

    print_section("File Context")
    print(f"Name           : {context['name']}")
    print(f"Type           : {context['type']}")
    print(f"Extension      : {context['extension']}")
    print(f"Size           : {context['size']} bytes")

    print_section("Hashes")
    print(f"MD5            : {context['md5']}")
    print(f"SHA1           : {context['sha1']}")
    print(f"SHA256         : {context['sha256']}")

    print_section("Timeline")
    print(f"First Submitted: {timeline['first_submission']}")
    print(f"Last Submitted : {timeline['last_submission']}")
    print(f"Last Analysis  : {timeline['last_analysis']}")

    if context["tags"]:
        print(f"\nTags           : {', '.join(context['tags'])}")

    if result["sandbox"]:
        print_section("Sandbox")

        for sandbox, verdict in result["sandbox"].items():
            tone = "danger" if verdict == "malicious" else "warning" if verdict == "suspicious" else "muted"
            print(f"{sandbox:<14}: {color_text(verdict, tone)}")


def query_safely(provider, query, artifact):
    try:
        return query(artifact)
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        print_error(f"{artifact}: {provider} HTTP error {status}")
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        print_error(f"{artifact}: {provider} unavailable ({exc})")
    return None


def main(argv=None):
    load_dotenv()
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        text = " ".join(argv)
    else:
        try:
            text = pyperclip.paste()
        except pyperclip.PyperclipException as exc:
            print_error(f"Cannot read clipboard: {exc}")
            return 1

    indicators = (
        [(ip, "ip") for ip in ip_extraction(text)]
        + [(domain, "domain") for domain in domain_extraction(text)]
        + [(value.lower(), "file") for value in hash_extraction(text)]
    )
    if not indicators:
        print("No supported IOCs found (public IPv4, domain, MD5, SHA1, SHA256).")
        return 1

    failed = False
    for artifact, kind in dict.fromkeys(indicators):
        vt = query_safely("VirusTotal", query_vt, artifact)
        failed |= vt is None
        if kind == "ip":
            abuse = query_safely("AbuseIPDB", query_abuse, artifact)
            failed |= abuse is None
            result = normalize_ip_result(vt, abuse, artifact)
        elif vt is None:
            continue
        elif kind == "domain":
            result = normalize_domain_result(vt)
        else:
            result = normalize_file_result(vt)
        print_analysis(result)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

