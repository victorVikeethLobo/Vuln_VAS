import os
import requests
from packaging.version import Version, InvalidVersion


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def normalize_version(version):
    """
    Convert a software version into a comparable Version object.
    Returns None if the version cannot be parsed.
    """

    if not version:
        return None

    version = version.strip()

    # Remove common prefixes
    for prefix in ["v", "version "]:
        if version.lower().startswith(prefix):
            version = version[len(prefix):].strip()

    try:
        return Version(version)

    except InvalidVersion:
        return None


def version_in_range(
    version,
    start_including=None,
    start_excluding=None,
    end_including=None,
    end_excluding=None
):
    """
    Determine whether a detected software version falls
    inside an NVD-defined vulnerable version range.
    """

    detected = normalize_version(version)

    if detected is None:
        return False

    if start_including:

        start = normalize_version(start_including)

        if start and detected < start:
            return False

    if start_excluding:

        start = normalize_version(start_excluding)

        if start and detected <= start:
            return False

    if end_including:

        end = normalize_version(end_including)

        if end and detected > end:
            return False

    if end_excluding:

        end = normalize_version(end_excluding)

        if end and detected >= end:
            return False

    return True


def cpe_matches_version(cpe_match, version):
    """
    Check whether a detected software version is affected
    according to an NVD CPE match.
    """

    return version_in_range(
        version,
        start_including=cpe_match.get("versionStartIncluding"),
        start_excluding=cpe_match.get("versionStartExcluding"),
        end_including=cpe_match.get("versionEndIncluding"),
        end_excluding=cpe_match.get("versionEndExcluding")
    )


def configuration_affects_version(configuration, version):
    """
    Evaluate NVD configuration nodes and determine whether
    the detected version is affected.
    """

    nodes = configuration.get("nodes", [])

    for node in nodes:

        cpe_matches = node.get("cpeMatch", [])

        for match in cpe_matches:

            # Ignore CPE entries explicitly marked as non-vulnerable
            if match.get("vulnerable") is False:
                continue

            # If there are no version restrictions, the CPE is
            # potentially applicable.
            has_version_range = any([
                match.get("versionStartIncluding"),
                match.get("versionStartExcluding"),
                match.get("versionEndIncluding"),
                match.get("versionEndExcluding")
            ])

            if not has_version_range:

                criteria = match.get("criteria", "")

                # Extract exact CPE version where possible
                parts = criteria.split(":")

                if len(parts) >= 6:

                    cpe_version = parts[5]

                    if cpe_version in ("*", "-"):
                        return True

                    if normalize_version(cpe_version) == normalize_version(version):
                        return True

                    continue

            if cpe_matches_version(match, version):
                return True

    return False


def search_cve(service, version):

    service = (service or "").strip()
    version = (version or "").strip()

    # -------------------------------------------------
    # Require version information
    # -------------------------------------------------

    if not service or not version:

        print(
            f"[!] Skipping CVE lookup: insufficient "
            f"product/version information for {service or 'unknown'}"
        )

        return []

    print(f"[+] Searching CVEs for {service} {version}")

    params = {
        "keywordSearch": f"{service} {version}",
        "resultsPerPage": 20,
        "noRejected": ""
    }

    headers = {}

    api_key = os.getenv("NVD_API_KEY")

    if api_key:
        headers["apiKey"] = api_key

    try:

        response = requests.get(
            NVD_API,
            params=params,
            headers=headers,
            timeout=15
        )

        response.raise_for_status()

        data = response.json()

    except requests.RequestException as e:

        print(f"[!] NVD request failed: {e}")

        return []

    except ValueError:

        print("[!] NVD returned invalid JSON.")

        return []

    results = []

    for item in data.get("vulnerabilities", []):

        cve_data = item.get("cve", {})

        cve_id = cve_data.get("id")

        if not cve_id:
            continue

        # -------------------------------------------------
        # VERSION VALIDATION
        # -------------------------------------------------

        configurations = cve_data.get("configurations", [])

        if not configurations:

            print(
                f"[!] Skipping {cve_id}: "
                f"no NVD version configuration"
            )

            continue

        affected = False

        for configuration in configurations:

            if configuration_affects_version(
                configuration,
                version
            ):

                affected = True
                break

        if not affected:

            print(
                f"[-] Version mismatch: "
                f"{cve_id} does not affect {service} {version}"
            )

            continue

        # -------------------------------------------------
        # CVSS
        # -------------------------------------------------

        metrics = cve_data.get("metrics", {})

        cvss_score = 0
        severity = "Unknown"

        if metrics.get("cvssMetricV31"):

            metric = metrics["cvssMetricV31"][0]

            cvss_data = metric.get("cvssData", {})

            cvss_score = cvss_data.get(
                "baseScore",
                0
            )

            severity = cvss_data.get(
                "baseSeverity",
                "Unknown"
            )

        elif metrics.get("cvssMetricV30"):

            metric = metrics["cvssMetricV30"][0]

            cvss_data = metric.get("cvssData", {})

            cvss_score = cvss_data.get(
                "baseScore",
                0
            )

            severity = cvss_data.get(
                "baseSeverity",
                "Unknown"
            )

        elif metrics.get("cvssMetricV2"):

            metric = metrics["cvssMetricV2"][0]

            cvss_data = metric.get("cvssData", {})

            cvss_score = cvss_data.get(
                "baseScore",
                0
            )

            severity = "Unknown"

        results.append({
            "service": service,
            "version": version,
            "cve": cve_id,
            "cvss": cvss_score,
            "severity": severity,
            "correlation": "version_match",
            "confidence": "high"
        })

    return results
