def normalize_cpe(cpe):
    """
    Normalize CPE 2.2 / CPE 2.3 URI-style representations
    into a comparable identity.

    This is intended for correlation/evidence comparison,
    not for replacing the original CPE stored in reports.
    """

    if not cpe:
        return None

    cpe = cpe.strip()

    # CPE 2.2 / URI format
    if cpe.startswith("cpe:/"):

        parts = cpe[5:].split(":")

        if len(parts) < 3:
            return None

        part = parts[0]
        vendor = parts[1]
        product = parts[2]

        return f"{part}:{vendor}:{product}"

    # CPE 2.3 formatted string
    if cpe.startswith("cpe:2.3:"):

        parts = cpe.split(":")

        if len(parts) < 4:
            return None

        part = parts[2]
        vendor = parts[3]
        product = parts[4]

        return f"{part}:{vendor}:{product}"

    return None


def cpes_represent_same_product(cpe1, cpe2):
    """
    Determine whether two CPE representations refer
    to the same product identity.
    """

    normalized1 = normalize_cpe(cpe1)
    normalized2 = normalize_cpe(cpe2)

    if not normalized1 or not normalized2:
        return False

    return normalized1 == normalized2
"""
CPE normalization utilities for VulnVAS.

Converts legacy CPE 2.2 URIs into CPE 2.3 strings
and applies known vendor/product mappings required
for accurate NVD correlation.
"""

import re


# ---------------------------------------------------------
# Known vendor mappings
# ---------------------------------------------------------

CPE_VENDOR_MAP = {
    "vsftpd": "vsftpd_project",
}


# ---------------------------------------------------------
# Legacy CPE 2.2 -> CPE 2.3
# ---------------------------------------------------------

def normalize_cpe(cpe):
    """
    Normalize a legacy CPE URI.

    Example:

        cpe:/a:vsftpd:vsftpd:2.3.4

    becomes:

        cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*
    """

    if not cpe:
        return ""

    cpe = cpe.strip()

    # Already CPE 2.3
    if cpe.startswith("cpe:2.3:"):
        return cpe

    # Legacy CPE 2.2 format
    if not cpe.startswith("cpe:/"):
        return cpe

    value = cpe[5:]

    parts = value.split(":")

    if len(parts) < 3:
        return cpe

    part = parts[0]
    vendor = parts[1]
    product = parts[2]

    version = parts[3] if len(parts) > 3 else "*"

    # Apply vendor mapping
    vendor = CPE_VENDOR_MAP.get(
        vendor.lower(),
        vendor
    )

    # CPE 2.3 has 11 fields after cpe:2.3
    fields = [
        part,
        vendor,
        product,
        version,
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*"
    ]

    return "cpe:2.3:" + ":".join(fields)


# ---------------------------------------------------------
# Product equivalence
# ---------------------------------------------------------

def cpes_represent_same_product(cpe1, cpe2):
    """
    Determine whether two CPEs represent the same
    vendor/product combination.
    """

    if not cpe1 or not cpe2:
        return False

    cpe1 = normalize_cpe(cpe1)
    cpe2 = normalize_cpe(cpe2)

    parts1 = cpe1.split(":")
    parts2 = cpe2.split(":")

    if len(parts1) < 5 or len(parts2) < 5:
        return False

    return (
        parts1[2].lower() == parts2[2].lower()
        and
        parts1[3].lower() == parts2[3].lower()
    )


# ---------------------------------------------------------
# CPE validation
# ---------------------------------------------------------

def is_valid_cpe(cpe):
    """
    Basic validation for a CPE 2.3 string.
    """

    if not cpe:
        return False

    cpe = normalize_cpe(cpe)

    if not cpe.startswith("cpe:2.3:"):
        return False

    parts = cpe.split(":")

    # cpe + 11 CPE attributes = 13 fields
    if len(parts) != 13:
        return False

    return True


# ---------------------------------------------------------
# Correlation suitability
# ---------------------------------------------------------

def is_valid_cpe_for_correlation(cpe):
    """
    Reject generic OS CPEs and incomplete CPEs
    from service-level CVE correlation.
    """

    if not is_valid_cpe(cpe):
        return False

    cpe = normalize_cpe(cpe)

    parts = cpe.split(":")

    if len(parts) != 13:
        return False

    part = parts[2]
    vendor = parts[3]
    product = parts[4]
    version = parts[5]

    # Service/application CPEs should use application part.
    if part != "a":
        return False

    # Reject generic/unknown identifiers.
    if vendor in ("", "*", "-"):
        return False

    if product in ("", "*", "-"):
        return False

    # Version should be present for exact service correlation.
    if version in ("", "*", "-"):
        return False

    return True
