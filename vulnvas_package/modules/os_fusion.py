from vulnvas_package.modules.cpe_normalizer import (
    cpes_represent_same_product
)
def fuse_os_evidence(host_info, os_detection):
    """
    Combine independent OS fingerprints.

    This function is deliberately conservative:
    it does not select an OS merely because Nmap
    assigns it the highest percentage.
    """

    result = {
        "status": "insufficient",
        "confidence": "low",
        "selected_cpe": None,
        "selected_os": None,
        "reason": "",
        "evidence": []
    }

    # -------------------------------------------------
    # RDP evidence
    # -------------------------------------------------

    rdp_version = host_info.get(
        "os_version",
        ""
    )

    if rdp_version:

        result["evidence"].append({
            "source": "rdp-ntlm-info",
            "product_version": rdp_version
        })

    # -------------------------------------------------
    # Nmap OS candidates
    # -------------------------------------------------

    candidates = os_detection.get(
        "candidates",
        []
    )

    for candidate in candidates:

        result["evidence"].append({
            "source": "nmap-os-detection",
            "name": candidate.get(
                "name",
                ""
            ),
            "accuracy": candidate.get(
                "accuracy",
                0
            ),
            "cpe": candidate.get(
                "cpe",
                ""
            )
        })

    # -------------------------------------------------
    # No Nmap candidates
    # -------------------------------------------------

    if not candidates:

        if rdp_version:

            result["status"] = "ambiguous"
            result["confidence"] = "low"
            result["reason"] = (
                "Windows build was identified by "
                "RDP, but no independent OS product "
                "identification was available."
            )

        return result

    # -------------------------------------------------
    # Determine highest Nmap candidate
    # -------------------------------------------------

    candidates = sorted(
        candidates,
        key=lambda x: x.get(
            "accuracy",
            0
        ),
        reverse=True
    )

    best = candidates[0]

    second = (
        candidates[1]
        if len(candidates) > 1
        else None
    )

    best_accuracy = best.get(
        "accuracy",
        0
    )

    second_accuracy = (
        second.get(
            "accuracy",
            0
        )
        if second
        else 0
    )

    # -------------------------------------------------
    # Conservative confidence rule
    # -------------------------------------------------

    # Require a strong lead over the next candidate.
    #
    # Example:
    # 96 vs 91 -> ambiguous
    # 96 vs 70 -> potentially strong
    #
    # We still do not automatically claim an OS
    # solely from Nmap.
    if (
        best_accuracy >= 95
        and
        (best_accuracy - second_accuracy) >= 10
    ):

        result["status"] = "candidate"
        result["confidence"] = "medium"
        result["selected_os"] = best.get(
            "name"
        )
        result["selected_cpe"] = best.get(
            "cpe"
        )
        result["reason"] = (
            "Nmap produced a strong leading OS "
            "candidate, but additional validation "
            "is recommended before OS-level CVE "
            "correlation."
        )

        return result

    # -------------------------------------------------
    # Ambiguous result
    # -------------------------------------------------

    result["status"] = "ambiguous"
    result["confidence"] = "low"
    result["reason"] = (
        "Multiple OS candidates remain plausible; "
        "no sufficiently strong independent evidence "
        "supports selecting a single OS CPE."
    )

    return result
from vulnvas_package.modules.cpe_normalizer import (
    cpes_represent_same_product
)


def fuse_os_evidence(host_info, os_detection):
    """
    Combine independent OS fingerprint evidence.

    Evidence sources:
    1. RDP NTLM product/build information
    2. Windows build mapping
    3. Nmap OS detection

    The function is deliberately conservative:
    it only selects an OS when independent evidence
    provides sufficient support.
    """

    result = {
        "status": "insufficient",
        "confidence": "low",
        "selected_cpe": None,
        "selected_os": None,
        "reason": "",
        "evidence": []
    }

    # -------------------------------------------------
    # RDP evidence
    # -------------------------------------------------

    rdp_version = host_info.get(
        "os_version",
        ""
    )

    if rdp_version:

        result["evidence"].append({
            "source": "rdp-ntlm-info",
            "product_version": rdp_version
        })

    # -------------------------------------------------
    # Windows build fingerprint
    # -------------------------------------------------

    windows_fingerprint = host_info.get(
        "windows_fingerprint",
        {}
    )

    build_status = windows_fingerprint.get(
        "status",
        ""
    )

    build_candidates = windows_fingerprint.get(
        "candidates",
        []
    )

    if build_candidates:

        result["evidence"].append({
            "source": "windows-build-mapping",
            "status": build_status,
            "candidates": build_candidates
        })

    # -------------------------------------------------
    # Nmap OS candidates
    # -------------------------------------------------

    candidates = os_detection.get(
        "candidates",
        []
    )

    for candidate in candidates:

        result["evidence"].append({
            "source": "nmap-os-detection",
            "name": candidate.get(
                "name",
                ""
            ),
            "accuracy": candidate.get(
                "accuracy",
                0
            ),
            "cpe": candidate.get(
                "cpe",
                ""
            )
        })

    # -------------------------------------------------
    # No useful OS evidence
    # -------------------------------------------------

    if not rdp_version and not build_candidates and not candidates:

        result["status"] = "insufficient"
        result["confidence"] = "low"

        result["reason"] = (
            "No reliable operating-system evidence "
            "was available."
        )

        return result

    # -------------------------------------------------
    # No Nmap candidates
    # -------------------------------------------------

    if not candidates:

        if build_candidates:

            if build_status == "identified":

                result["status"] = "candidate"
                result["confidence"] = "medium"

                result["selected_os"] = (
                    f"{build_candidates[0].get('product', '')} "
                    f"{build_candidates[0].get('release', '')}"
                ).strip()

                result["selected_cpe"] = (
                    build_candidates[0].get("cpe")
                )

                result["reason"] = (
                    "The Windows build mapping identified "
                    "a unique OS candidate, but no independent "
                    "Nmap OS identification was available."
                )

            else:

                result["status"] = "ambiguous"
                result["confidence"] = "low"

                result["reason"] = (
                    "Windows build information was available, "
                    "but it did not uniquely identify an OS."
                )

        elif rdp_version:

            result["status"] = "ambiguous"
            result["confidence"] = "low"

            result["reason"] = (
                "Windows build information was obtained "
                "from RDP, but no independent OS product "
                "identification was available."
            )

        else:

            result["status"] = "insufficient"
            result["confidence"] = "low"

            result["reason"] = (
                "No independent OS product identification "
                "was available."
            )

        return result

    # -------------------------------------------------
    # Sort Nmap candidates by accuracy
    # -------------------------------------------------

    candidates = sorted(
        candidates,
        key=lambda x: x.get(
            "accuracy",
            0
        ),
        reverse=True
    )

    best = candidates[0]

    second = (
        candidates[1]
        if len(candidates) > 1
        else None
    )

    best_accuracy = best.get(
        "accuracy",
        0
    )

    second_accuracy = (
        second.get(
            "accuracy",
            0
        )
        if second
        else 0
    )

    # -------------------------------------------------
    # Build CPE set
    # -------------------------------------------------

    build_cpes = []

    for candidate in build_candidates:

        cpe = candidate.get(
            "cpe",
            ""
        )

        if cpe:

            build_cpes.append(
                cpe
            )

    # -------------------------------------------------
    # Compare Nmap CPE with Windows build CPE
    #
    # Handles:
    #
    # CPE 2.2:
    # cpe:/o:microsoft:windows_server_2019
    #
    # CPE 2.3:
    # cpe:2.3:o:microsoft:windows_server_2019:*...
    # -------------------------------------------------

    agreement = []

    if build_cpes:

        for nmap_candidate in candidates:

            nmap_cpe = nmap_candidate.get(
                "cpe",
                ""
            )

            if not nmap_cpe:

                continue

            for build_cpe in build_cpes:

                if cpes_represent_same_product(
                    nmap_cpe,
                    build_cpe
                ):

                    agreement.append(
                        nmap_candidate
                    )

                    break

    # -------------------------------------------------
    # Strong independent agreement
    # -------------------------------------------------

    if agreement:

        best_agreement = max(
            agreement,
            key=lambda x: x.get(
                "accuracy",
                0
            )
        )

        agreement_accuracy = (
            best_agreement.get(
                "accuracy",
                0
            )
        )

        if (
            build_status == "identified"
            and agreement_accuracy >= 90
        ):

            result["status"] = "identified"
            result["confidence"] = "high"

            result["selected_cpe"] = (
                best_agreement.get(
                    "cpe"
                )
            )

            result["selected_os"] = (
                best_agreement.get(
                    "name"
                )
            )

            result["reason"] = (
                "The Windows build mapping identifies "
                "a unique OS candidate and independent "
                "Nmap OS detection agrees with the same "
                "product."
            )

            return result

        # -------------------------------------------------
        # Agreement exists but build mapping isn't unique
        # -------------------------------------------------

    # -------------------------------------------------
    # Strong Nmap candidate with a significant lead
    # -------------------------------------------------

    if (
        best_accuracy >= 95
        and
        (best_accuracy - second_accuracy) >= 10
    ):

        result["status"] = "candidate"
        result["confidence"] = "medium"

        result["selected_cpe"] = (
            best.get(
                "cpe"
            )
        )

        result["selected_os"] = (
            best.get(
                "name"
            )
        )

        result["reason"] = (
            "Nmap produced a strong leading OS candidate, "
            "but additional independent validation is "
            "recommended before OS-level CVE correlation."
        )

        return result

    # -------------------------------------------------
    # Single high-confidence Nmap candidate
    # -------------------------------------------------

    if (
        len(candidates) == 1
        and best_accuracy >= 95
    ):

        result["status"] = "candidate"
        result["confidence"] = "medium"

        result["selected_cpe"] = (
            best.get(
                "cpe"
            )
        )

        result["selected_os"] = (
            best.get(
                "name"
            )
        )

        result["reason"] = (
            "Nmap produced a single high-confidence "
            "OS candidate, but additional independent "
            "validation is recommended."
        )

        return result

    # -------------------------------------------------
    # Ambiguous
    # -------------------------------------------------

    result["status"] = "ambiguous"
    result["confidence"] = "low"

    result["selected_cpe"] = None
    result["selected_os"] = None

    result["reason"] = (
        "Multiple OS candidates remain plausible; "
        "no sufficiently strong independent evidence "
        "supports selecting a single OS CPE."
    )

    return result
