import requests
from packaging.version import Version, InvalidVersion

from vulnvas_package.modules.cpe_normalizer import normalize_cpe


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ============================================================
# CPE HELPERS
# ============================================================

def _unescape_cpe(value):
    """
    Basic CPE escaping cleanup.

    Examples:

        cpe:/a:apache:http_server:2.4.62

    or:

        cpe:2.3:a:apache:http_server:2.4.62:*:*:*:*:*:*:*
    """

    if value is None:
        return ""

    return (
        value
        .replace("\\:", ":")
        .replace("\\!", "!")
        .replace("\\*", "*")
        .replace("\\?", "?")
        .strip()
    )


def parse_cpe(cpe):
    """
    Parse both legacy CPE URI and CPE 2.3.

    Returns:

        {
            "part": ...,
            "vendor": ...,
            "product": ...,
            "version": ...
        }

    or None if invalid.
    """

    if not cpe:
        return None

    cpe = _unescape_cpe(cpe)

    # --------------------------------------------------------
    # CPE 2.3
    #
    # cpe:2.3:part:vendor:product:version:...
    # --------------------------------------------------------

    if cpe.startswith("cpe:2.3:"):

        parts = cpe.split(":")

        if len(parts) < 6:
            return None

        return {
            "part": parts[2],
            "vendor": parts[3],
            "product": parts[4],
            "version": parts[5],
        }

    # --------------------------------------------------------
    # Legacy CPE URI
    #
    # cpe:/part:vendor:product:version
    # --------------------------------------------------------

    if cpe.startswith("cpe:/"):

        value = cpe[5:]
        parts = value.split(":")

        if len(parts) < 3:
            return None

        return {
            "part": parts[0] if len(parts) > 0 else "",
            "vendor": parts[1] if len(parts) > 1 else "",
            "product": parts[2] if len(parts) > 2 else "",
            "version": parts[3] if len(parts) > 3 else "",
        }

    return None


def normalize_product(value):
    """
    Normalize vendor/product strings for comparison.
    """

    if not value:
        return ""

    value = _unescape_cpe(value).lower()

    value = value.replace("-", "_")
    value = value.replace(" ", "_")

    return value


# ============================================================
# VERSION HELPERS
# ============================================================

def versions_equal(v1, v2):
    """
    Compare versions safely.

    Falls back to string comparison when packaging
    cannot interpret the version.
    """

    if not v1 or not v2:
        return False

    v1 = v1.strip()
    v2 = v2.strip()

    try:
        return Version(v1) == Version(v2)

    except InvalidVersion:
        return v1.lower() == v2.lower()


def version_compare(v1, v2):
    """
    Returns:

        -1 -> v1 < v2
         0 -> v1 == v2
         1 -> v1 > v2

    Returns None if versions cannot be compared.
    """

    if not v1 or not v2:
        return None

    try:

        a = Version(v1)
        b = Version(v2)

        if a < b:
            return -1

        if a > b:
            return 1

        return 0

    except InvalidVersion:

        return None


# ============================================================
# CPE MATCHING
# ============================================================

def cpe_product_matches(detected_cpe, criteria_cpe):
    """
    Determine whether the vendor/product/part in the NVD
    CPE criteria represents the same product as the
    detected CPE.
    """

    detected = parse_cpe(detected_cpe)
    criteria = parse_cpe(criteria_cpe)

    if not detected or not criteria:
        return False

    # --------------------------------------------------------
    # Part
    # --------------------------------------------------------

    detected_part = normalize_product(
        detected.get("part", "")
    )

    criteria_part = normalize_product(
        criteria.get("part", "")
    )

    if criteria_part not in ("", "*", "-"):

        if detected_part != criteria_part:
            return False

    # --------------------------------------------------------
    # Vendor
    # --------------------------------------------------------

    detected_vendor = normalize_product(
        detected.get("vendor", "")
    )

    criteria_vendor = normalize_product(
        criteria.get("vendor", "")
    )

    if criteria_vendor not in ("", "*", "-"):

        if detected_vendor != criteria_vendor:
            return False

    # --------------------------------------------------------
    # Product
    # --------------------------------------------------------

    detected_product = normalize_product(
        detected.get("product", "")
    )

    criteria_product = normalize_product(
        criteria.get("product", "")
    )

    if criteria_product not in ("", "*", "-"):

        if detected_product != criteria_product:
            return False

    return True


def version_is_affected(
    detected_version,
    criteria_version,
    match
):
    """
    Validate the detected version against an NVD
    CPE match criterion.

    Handles:

        exact versions
        *
        -
        versionStartIncluding
        versionStartExcluding
        versionEndIncluding
        versionEndExcluding
    """

    if not detected_version:
        return False

    detected_version = detected_version.strip()

    # --------------------------------------------------------
    # Version boundaries
    # --------------------------------------------------------

    start_including = match.get(
        "versionStartIncluding"
    )

    start_excluding = match.get(
        "versionStartExcluding"
    )

    end_including = match.get(
        "versionEndIncluding"
    )

    end_excluding = match.get(
        "versionEndExcluding"
    )

    # --------------------------------------------------------
    # Start including
    # --------------------------------------------------------

    if start_including:

        comparison = version_compare(
            detected_version,
            start_including
        )

        if comparison is None:
            return False

        if comparison < 0:
            return False

    # --------------------------------------------------------
    # Start excluding
    # --------------------------------------------------------

    if start_excluding:

        comparison = version_compare(
            detected_version,
            start_excluding
        )

        if comparison is None:
            return False

        if comparison <= 0:
            return False

    # --------------------------------------------------------
    # End including
    # --------------------------------------------------------

    if end_including:

        comparison = version_compare(
            detected_version,
            end_including
        )

        if comparison is None:
            return False

        if comparison > 0:
            return False

    # --------------------------------------------------------
    # End excluding
    # --------------------------------------------------------

    if end_excluding:

        comparison = version_compare(
            detected_version,
            end_excluding
        )

        if comparison is None:
            return False

        if comparison >= 0:
            return False

    # --------------------------------------------------------
    # If an explicit range exists, version passed it
    # --------------------------------------------------------

    if (
        start_including
        or start_excluding
        or end_including
        or end_excluding
    ):

        return True

    # --------------------------------------------------------
    # Exact CPE version
    # --------------------------------------------------------

    if criteria_version in ("", "*", "-"):

        # Wildcard version means all versions of this
        # product are potentially covered.
        return True

    return versions_equal(
        detected_version,
        criteria_version
    )


def cpe_match_is_applicable(
    detected_cpe,
    detected_version,
    match
):
    """
    Validate one NVD cpeMatch object.

    Requirements:

        1. vulnerable must be True
        2. vendor/product/part must match
        3. version must match
    """

    if not match.get("vulnerable", False):
        return False

    criteria_cpe = match.get(
        "criteria",
        ""
    )

    if not criteria_cpe:
        return False

    # --------------------------------------------------------
    # Product identity
    # --------------------------------------------------------

    if not cpe_product_matches(
        detected_cpe,
        criteria_cpe
    ):
        return False

    # --------------------------------------------------------
    # Version
    # --------------------------------------------------------

    criteria = parse_cpe(
        criteria_cpe
    )

    if not criteria:
        return False

    return version_is_affected(
        detected_version,
        criteria.get("version", ""),
        match
    )


# ============================================================
# NVD CONFIGURATION TREE
# ============================================================

def node_contains_match(
    node,
    detected_cpe,
    detected_version
):
    """
    Recursively evaluate an NVD configuration node.

    NVD configurations can contain nested
    AND / OR nodes.
    """

    if not node:
        return False

    matches = node.get(
        "cpeMatch",
        []
    )

    child_nodes = node.get(
        "nodes",
        []
    )

    results = []

    # --------------------------------------------------------
    # Direct CPE matches
    # --------------------------------------------------------

    for match in matches:

        result = cpe_match_is_applicable(
            detected_cpe,
            detected_version,
            match
        )

        results.append(result)

    # --------------------------------------------------------
    # Child nodes
    # --------------------------------------------------------

    for child in child_nodes:

        results.append(
            node_contains_match(
                child,
                detected_cpe,
                detected_version
            )
        )

    if not results:
        return False

    operator = node.get(
        "operator",
        "OR"
    ).upper()

    negate = node.get(
        "negate",
        False
    )

    # --------------------------------------------------------
    # AND
    # --------------------------------------------------------

    if operator == "AND":

        result = all(results)

    # --------------------------------------------------------
    # OR
    # --------------------------------------------------------

    else:

        result = any(results)

    if negate:
        result = not result

    return result


def cve_affects_detected_cpe(
    cve,
    detected_cpe,
    detected_version
):
    """
    Determine whether a CVE actually applies to the
    detected CPE/version according to the NVD
    configuration.
    """

    configurations = cve.get(
        "configurations",
        []
    )

    if not configurations:
        return False

    for configuration in configurations:

        if node_contains_match(
            configuration,
            detected_cpe,
            detected_version
        ):
            return True

    return False


# ============================================================
# CVSS
# ============================================================

def extract_cvss(cve):
    """
    Extract the best available CVSS score.

    Preference:

        CVSS v3.1
        CVSS v3.0
        CVSS v2
    """

    metrics = cve.get(
        "metrics",
        {}
    )

    # --------------------------------------------------------
    # CVSS v3.1
    # --------------------------------------------------------

    if metrics.get("cvssMetricV31"):

        metric = metrics[
            "cvssMetricV31"
        ][0]

        data = metric.get(
            "cvssData",
            {}
        )

        return (
            data.get(
                "baseScore",
                0
            ),
            data.get(
                "baseSeverity",
                ""
            )
        )

    # --------------------------------------------------------
    # CVSS v3.0
    # --------------------------------------------------------

    if metrics.get("cvssMetricV30"):

        metric = metrics[
            "cvssMetricV30"
        ][0]

        data = metric.get(
            "cvssData",
            {}
        )

        return (
            data.get(
                "baseScore",
                0
            ),
            data.get(
                "baseSeverity",
                ""
            )
        )

    # --------------------------------------------------------
    # CVSS v2
    # --------------------------------------------------------

    if metrics.get("cvssMetricV2"):

        metric = metrics[
            "cvssMetricV2"
        ][0]

        data = metric.get(
            "cvssData",
            {}
        )

        return (
            data.get(
                "baseScore",
                0
            ),
            metric.get(
                "baseSeverity",
                ""
            )
        )

    return 0, "Unknown"


def normalize_severity(
    score,
    nvd_severity
):
    """
    Use NVD severity where available.

    Otherwise derive severity from CVSS score.
    """

    if nvd_severity:

        value = str(
            nvd_severity
        ).upper()

        if value in {
            "NONE",
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL"
        }:

            return value

    try:

        score = float(score)

    except (
        TypeError,
        ValueError
    ):

        return "Unknown"

    if score == 0:
        return "None"

    if score < 4.0:
        return "LOW"

    if score < 7.0:
        return "MEDIUM"

    if score < 9.0:
        return "HIGH"

    return "CRITICAL"


# ============================================================
# NVD REQUEST
# ============================================================

def _query_nvd_by_cpe(normalized_cpe):
    """
    Query NVD using a normalized CPE 2.3 string.

    Returns the parsed JSON response or None.
    """

    params = {
        "cpeName": normalized_cpe,
        "isVulnerable": "",
        "resultsPerPage": 200
    }

    try:

        response = requests.get(
            NVD_API,
            params=params,
            timeout=20,
            headers={
                "User-Agent": "VulnVAS/1.0"
            }
        )

        # NVD can return 404 when the supplied CPE
        # is not a recognized CPE name.
        if response.status_code == 404:

            print(
                "[!] NVD does not recognize CPE:"
                f" {normalized_cpe}"
            )

            return None

        response.raise_for_status()

        return response.json()

    except requests.RequestException as e:

        print(
            "[!] NVD CPE lookup failed:",
            e
        )

        return None

    except ValueError as e:

        print(
            "[!] NVD returned invalid JSON:",
            e
        )

        return None


# ============================================================
# SEARCH
# ============================================================

def search_cve(
    service,
    version,
    cpe=None
):
    """
    Search NVD and perform STRICT CPE/version correlation.

    Flow:

        detected CPE
            ↓
        normalize CPE
            ↓
        parse CPE
            ↓
        NVD CPE lookup
            ↓
        configuration validation
            ↓
        version validation
            ↓
        CVSS extraction
            ↓
        vulnerability result

    Keyword search is deliberately NOT used as a fallback,
    because doing so can produce false-positive CVEs.
    """

    # --------------------------------------------------------
    # Basic validation
    # --------------------------------------------------------

    if not service or not version:

        print(
            "[!] Skipping CVE lookup: "
            "insufficient product/version information "
            f"for {service}"
        )

        return []

    if not cpe:

        print(
            "[!] Skipping CVE lookup: "
            f"no usable CPE for "
            f"{service} {version}"
        )

        return []

    # --------------------------------------------------------
    # Normalize CPE
    # --------------------------------------------------------

    normalized_cpe = normalize_cpe(
        cpe
    )

    if not normalized_cpe:

        print(
            "[!] Skipping CVE lookup: "
            f"unable to normalize CPE for "
            f"{service} {version}: {cpe}"
        )

        return []

    print(
        f"[+] Normalized CPE: "
        f"{cpe} -> {normalized_cpe}"
    )

    # --------------------------------------------------------
    # Parse normalized CPE
    # --------------------------------------------------------

    parsed_cpe = parse_cpe(
        normalized_cpe
    )

    if not parsed_cpe:

        print(
            "[!] Skipping CVE lookup: "
            f"invalid normalized CPE for "
            f"{service} {version}: "
            f"{normalized_cpe}"
        )

        return []

    # --------------------------------------------------------
    # Reject generic CPEs
    # --------------------------------------------------------

    part = parsed_cpe.get(
        "part",
        ""
    )

    vendor = parsed_cpe.get(
        "vendor",
        ""
    )

    product = parsed_cpe.get(
        "product",
        ""
    )

    if (
        part in ("", "*", "-")
        or
        vendor in ("", "*", "-")
        or
        product in ("", "*", "-")
    ):

        print(
            "[!] Skipping CVE lookup: "
            f"generic CPE for "
            f"{service} {version}: "
            f"{normalized_cpe}"
        )

        return []

    print(
        f"[+] Searching CVEs for "
        f"{service} {version}"
    )

    # --------------------------------------------------------
    # Query NVD
    # --------------------------------------------------------

    data = _query_nvd_by_cpe(
        normalized_cpe
    )

    if not data:

        return []

    vulnerabilities = []

    # --------------------------------------------------------
    # Process CVEs
    # --------------------------------------------------------

    for item in data.get(
        "vulnerabilities",
        []
    ):

        cve = item.get(
            "cve",
            {}
        )

        cve_id = cve.get(
            "id"
        )

        if not cve_id:
            continue

        # ----------------------------------------------------
        # Strict configuration validation
        # ----------------------------------------------------

        applicable = cve_affects_detected_cpe(
            cve,
            normalized_cpe,
            version
        )

        if not applicable:

            print(
                f"[-] Configuration mismatch: "
                f"{cve_id} does not affect "
                f"{service} {version}"
            )

            continue

        # ----------------------------------------------------
        # CVSS
        # ----------------------------------------------------

        cvss_score, nvd_severity = extract_cvss(
            cve
        )

        severity = normalize_severity(
            cvss_score,
            nvd_severity
        )

        # ----------------------------------------------------
        # Result
        # ----------------------------------------------------

        vulnerabilities.append({

            "service": service,

            "version": version,

            "cve": cve_id,

            "cvss": cvss_score,

            "severity": severity,

            "correlation": (
                "exact_cpe_version_match"
            ),

            "confidence": "high",

            "source_cpe": normalized_cpe

        })

    return vulnerabilities
