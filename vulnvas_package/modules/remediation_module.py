def remediation_advice(vuln):

    service = vuln["service"]
    severity = vuln["severity"]

    fixes = {
        "vsftpd": "Upgrade vsftpd to latest version and disable anonymous FTP.",
        "Apache": "Upgrade Apache to latest version and disable vulnerable modules.",
        "MySQL": "Update MySQL and restrict remote root access.",
        "Samba": "Update Samba and disable SMBv1.",
        "OpenSSH": "Upgrade OpenSSH and disable weak authentication methods.",
        "Tomcat": "Update Apache Tomcat and secure AJP connector."
    }

    return fixes.get(service.split()[0], "Update service to latest version and apply vendor patches.")
