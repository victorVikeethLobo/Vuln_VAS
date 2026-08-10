import subprocess
import requests
import nmap
from bs4 import BeautifulSoup
from vulnvas_package.modules.os_fusion import fuse_os_evidence
from vulnvas_package.modules.windows_fingerprint import map_windows_build


def http_fingerprint(target):

    try:

        url = f"http://{target}"

        r = requests.get(
            url,
            timeout=10
        )

        soup = BeautifulSoup(
            r.text,
            "html.parser"
        )

        return {
            "status_code": r.status_code,
            "server": r.headers.get(
                "Server",
                "Unknown"
            ),
            "title": (
                soup.title.string
                if soup.title
                else "No Title"
            )
        }

    except Exception as e:

        return {
            "error": str(e)
        }


def nmap_scan(target):

    nm = nmap.PortScanner()

    # Fast initial service/version discovery
    nm.scan(
        target,
        arguments="-sV -T4 -Pn"
    )

    services = []

    for host in nm.all_hosts():

        for proto in nm[host].all_protocols():

            ports = nm[host][proto].keys()

            for port in ports:

                data = nm[host][proto][port]

                service = {
                    "service": (
                        data.get("product")
                        or data.get("name")
                        or ""
                    ),

                    "version": (
                        data.get("version")
                        or ""
                    ),

                    "port": port,

                    "protocol": proto,

                    "extrainfo": (
                        data.get("extrainfo")
                        or ""
                    ),

                    "cpe": (
                        data.get("cpe")
                        or ""
                    )
                }

                services.append(service)

    return services


def run_targeted_enrichment(target, services):

    """
    Run service-specific NSE scripts only when useful
    fingerprint information is missing.
    """

    ports_to_enrich = []

    for service in services:

        port = service.get("port")

        version = service.get(
            "version",
            ""
        )

        # RDP enrichment
        if port == 3389 and not version:

            ports_to_enrich.append(
                "3389"
            )

        # SMB enrichment
        if port == 445 and (
            not service.get("service")
            or not service.get("cpe")
        ):

            ports_to_enrich.append(
                "445"
            )

    if not ports_to_enrich:

        return services

    ports_to_enrich = sorted(
        set(ports_to_enrich)
    )

    port_list = ",".join(
        str(port)
        for port in ports_to_enrich
    )

    scripts = []

    if "3389" in port_list:

        scripts.append(
            "rdp-ntlm-info"
        )

    if "445" in port_list:

        scripts.append(
            "smb-os-discovery"
        )

    if not scripts:

        return services

    script_list = ",".join(
        scripts
    )

    print(
        "[+] Running targeted NSE "
        f"enrichment: {script_list}"
    )

    try:

        nm = nmap.PortScanner()

        nm.scan(
            target,
            ports=port_list,
            arguments=(
                f"-Pn --script {script_list}"
            )
        )

    except Exception as e:

        print(
            f"[!] NSE enrichment failed: {e}"
        )

        return services

    # -------------------------------------------------
    # Process NSE results
    # -------------------------------------------------

    for service in services:

        port = service.get("port")

        if port not in [3389, 445]:

            continue

        try:

            if target not in nm.all_hosts():

                continue

            if "tcp" not in nm[target]:

                continue

            if port not in nm[target]["tcp"]:

                continue

            script_results = (
                nm[target]["tcp"][port]
                .get("script", {})
            )

        except Exception:

            continue

        # ---------------------------------------------
        # RDP enrichment
        # ---------------------------------------------

        if port == 3389:

            rdp_info = script_results.get(
                "rdp-ntlm-info",
                ""
            )

            service["nse"] = {
                "rdp-ntlm-info": rdp_info
            }

            if rdp_info:

                for raw_line in str(
                    rdp_info
                ).splitlines():

                    line = raw_line.strip()

                    if (
                        "Product_Version:"
                        in line
                    ):

                        product_version = (
                            line.split(
                                "Product_Version:",
                                1
                            )[1]
                            .strip()
                        )

                        if product_version:

                            service[
                                "discovered_version"
                            ] = product_version

                        break

        # ---------------------------------------------
        # SMB enrichment
        # ---------------------------------------------

        elif port == 445:

            smb_info = script_results.get(
                "smb-os-discovery",
                ""
            )

            service["nse"] = {
                "smb-os-discovery": smb_info
            }


    return services


def extract_host_info(services):

    """
    Extract host-level information from service
    fingerprints.

    Host information is kept separate from service
    versions to avoid incorrect CVE matching.
    """

    host_info = {

        "os": "",

        "os_version": "",

        "hostname": "",

        "domain": "",

        "source": ""
    }

    # -------------------------------------------------
    # Process service fingerprints
    # -------------------------------------------------

    for service in services:

        nse = service.get(
            "nse",
            {}
        )

        # ---------------------------------------------
        # RDP NTLM information
        # ---------------------------------------------

        rdp_info = nse.get(
            "rdp-ntlm-info",
            ""
        )

        if rdp_info:

            for raw_line in str(
                rdp_info
            ).splitlines():

                line = raw_line.strip()

                # Windows build
                if line.startswith(
                    "Product_Version:"
                ):

                    host_info[
                        "os_version"
                    ] = (
                        line.split(
                            "Product_Version:",
                            1
                        )[1]
                        .strip()
                    )

                    host_info[
                        "os"
                    ] = (
                        "Microsoft Windows"
                    )

                    host_info[
                        "source"
                    ] = (
                        "rdp-ntlm-info"
                    )

                # Computer hostname
                elif line.startswith(
                    "DNS_Computer_Name:"
                ):

                    host_info[
                        "hostname"
                    ] = (
                        line.split(
                            "DNS_Computer_Name:",
                            1
                        )[1]
                        .strip()
                    )

                # Domain
                elif line.startswith(
                    "DNS_Domain_Name:"
                ):

                    host_info[
                        "domain"
                    ] = (
                        line.split(
                            "DNS_Domain_Name:",
                            1
                        )[1]
                        .strip()
                    )

    # -------------------------------------------------
    # Windows build mapping
    # -------------------------------------------------

    if host_info["os_version"]:

        host_info[
            "windows_fingerprint"
        ] = map_windows_build(
            host_info["os_version"]
        )

    return host_info


def nikto_scan(target):

    cmd = [
        "nikto",
        "-h",
        f"http://{target}"
    ]

    try:

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        findings = []

        for line in result.stdout.splitlines():

            if line.startswith("+"):

                findings.append(line)

        return findings

    except subprocess.TimeoutExpired:

        return [
            "[!] Nikto scan timed out."
        ]

    except Exception as e:

        return [
            f"[!] Nikto scan failed: {e}"
        ]

def nmap_os_detection(target):
    """
    Run Nmap OS detection and preserve OS candidates.

    OS detection can be unreliable when the target does not
    provide suitable open/closed ports, so candidates are
    treated as evidence rather than confirmed identity.
    """

    print("[+] Running OS fingerprinting...")

    try:

        nm = nmap.PortScanner()

        nm.scan(
            target,
            arguments="-O -Pn"
        )

        if target not in nm.all_hosts():

            return {
                "status": "no_result",
                "candidates": []
            }

        host = nm[target]

        os_matches = host.get(
            "osmatch",
            []
        )

        candidates = []

        for match in os_matches:

            name = match.get(
                "name",
                ""
            )

            accuracy = match.get(
                "accuracy",
                "0"
            )

            for osclass in match.get(
                "osclass",
                []
            ):

                cpe_list = osclass.get(
                    "cpe",
                    []
                )

                for cpe in cpe_list:

                    candidates.append({
                        "name": name,
                        "accuracy": int(
                            accuracy
                        ),
                        "cpe": cpe
                    })

        # Remove duplicate candidates
        unique = {}

        for candidate in candidates:

            key = (
                candidate["name"],
                candidate["cpe"]
            )

            unique[key] = candidate

        candidates = list(
            unique.values()
        )

        if not candidates:

            return {
                "status": "no_match",
                "candidates": []
            }

        return {
            "status": "candidate_matches",
            "candidates": candidates
        }

    except Exception as e:

        print(
            f"[!] OS detection failed: {e}"
        )

        return {
            "status": "error",
            "error": str(e),
            "candidates": []
        }
def run_all_recon(target):

    print(
        "[+] Running Nmap service discovery..."
    )

    # ---------------------------------------------
    # HTTP fingerprint
    # ---------------------------------------------

    http = http_fingerprint(
        target
    )

    # ---------------------------------------------
    # Nmap
    # ---------------------------------------------

    services = nmap_scan(
        target
    )

    print(
        f"[+] Nmap discovered "
        f"{len(services)} services"
    )

    # ---------------------------------------------
    # Targeted NSE enrichment
    # ---------------------------------------------

    services = run_targeted_enrichment(
        target,
        services
    )

    # ---------------------------------------------
    # Host fingerprint
    # ---------------------------------------------

    host_info = extract_host_info(
        services
    )
    os_detection = nmap_os_detection(
        target
    )
    os_fusion = fuse_os_evidence(
        host_info,
        os_detection
)

    # ---------------------------------------------
    # Nikto
    # ---------------------------------------------

    nikto = nikto_scan(
        target
    )

    # ---------------------------------------------
    # Final recon result
    # ---------------------------------------------

    return {
         "target": target,
         "host_info": host_info,
         "os_detection": os_detection,
         "os_fusion": os_fusion,
         "http": http,
         "services": services,
         "nikto": nikto
}
