def is_valid_cpe_for_correlation(cpe):
    """
    Determine whether a CPE is specific enough for
    vulnerability correlation.

    Generic OS-family CPEs are deliberately rejected.
    """

    if not cpe:
        return False

    cpe = cpe.strip()

    # Reject legacy generic Windows OS CPE
    if cpe in (
        "cpe:/o:microsoft:windows",
        "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*:*"
    ):
        return False

    # CPE 2.3 format
    if cpe.startswith("cpe:2.3:"):

        parts = cpe.split(":")

        # cpe:2.3:type:vendor:product:...
        if len(parts) < 6:
            return False

        cpe_type = parts[2]
        vendor = parts[3]
        product = parts[4]

        if not vendor or not product:
            return False

        # Application CPEs are suitable for service correlation
        if cpe_type == "a":
            return True

        # OS CPEs should only come from the OS evidence-fusion
        # layer, not directly from service records.
        if cpe_type == "o":
            return False

        return False

    # Legacy CPE
    if cpe.startswith("cpe:/"):

        parts = cpe.split(":")

        if len(parts) < 4:
            return False

        cpe_type = parts[1]
        vendor = parts[2]
        product = parts[3]

        if not vendor or not product:
            return False

        if cpe_type == "a":
            return True

        return False

    return False
