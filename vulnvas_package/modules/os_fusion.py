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
