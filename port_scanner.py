
import socket


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    135: "MS RPC",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "Remote Desktop",
    5432: "PostgreSQL",
    8080: "HTTP Alternative"
}


def scan_ports(host="127.0.0.1"):
    """Check common TCP ports on the authorized target."""

    results = []

    for port, service in COMMON_PORTS.items():
        try:
            with socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            ) as sock:

                sock.settimeout(0.4)
                status = sock.connect_ex((host, port))

                if status == 0:
                    results.append({
                        "port": port,
                        "service": service,
                        "status": "Open"
                    })

        except OSError:
            continue

    return results
