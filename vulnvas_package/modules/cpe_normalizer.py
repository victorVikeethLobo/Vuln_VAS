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
