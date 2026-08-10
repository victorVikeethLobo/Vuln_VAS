import re


WINDOWS_BUILD_MAP = {
    "26100": {
        "candidates": [
            {
                "product": "Windows 11",
                "release": "24H2",
                "cpe": "cpe:2.3:o:microsoft:windows_11:24H2:*:*:*:*:*:*:*"
            },
            {
                "product": "Windows Server",
                "release": "2025",
                "cpe": "cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:*:*"
            }
        ]
    },

    "26200": {
        "candidates": [
            {
                "product": "Windows 11",
                "release": "25H2",
                "cpe": "cpe:2.3:o:microsoft:windows_11:25H2:*:*:*:*:*:*:*"
            }
        ]
    },

    "22631": {
        "candidates": [
            {
                "product": "Windows 11",
                "release": "23H2",
                "cpe": "cpe:2.3:o:microsoft:windows_11:23H2:*:*:*:*:*:*:*"
            }
        ]
    },

    "20348": {
        "candidates": [
            {
                "product": "Windows Server",
                "release": "2022",
                "cpe": "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*"
            }
        ]
    },

    "17763": {
        "candidates": [
            {
                "product": "Windows Server",
                "release": "2019",
                "cpe": "cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*"
            }
        ]
    }
}


def get_build_number(version):
    """
    Extract the major Windows build number.

    Example:
        10.0.26100
        -> 26100
    """

    if not version:
        return None

    match = re.search(
        r"10\.0\.(\d+)",
        str(version)
    )

    if match:
        return match.group(1)

    return None


def map_windows_build(version):
    """
    Map a Windows build to possible Windows products.

    This intentionally returns candidates instead of
    claiming a definitive OS/CPE when the build is shared
    by multiple Microsoft products.
    """

    build = get_build_number(version)

    if not build:
        return {
            "build": version,
            "status": "unknown",
            "candidates": []
        }

    mapping = WINDOWS_BUILD_MAP.get(build)

    if not mapping:
        return {
            "build": build,
            "status": "unknown_build",
            "candidates": []
        }

    candidates = mapping["candidates"]

    if len(candidates) == 1:
        status = "identified"
    else:
        status = "ambiguous"

    return {
        "build": build,
        "status": status,
        "candidates": candidates
    }
