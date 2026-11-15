
from datetime import datetime


def build_records(
    system_info,
    processes,
    open_ports,
    software=None,
    file_config=None
):
    """Convert all scanner outputs into a common record format."""

    scan_time = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

    records = []

    # 1. System information records
    for key, value in system_info.items():
        records.append({
            "scan_time": scan_time,
            "category": "System",
            "item": key,
            "description": str(value),
            "severity": "Informational",
            "recommendation": "System inventory observation."
        })

    # 2. Process records
    for process in processes:
        name = process.get("name") or "Unknown process"
        pid = process.get("pid")
        status = process.get("status") or "Unknown"
        username = process.get("username") or "Unavailable"

        records.append({
            "scan_time": scan_time,
            "category": "Process",
            "item": f"{name} (PID {pid})",
            "description": f"Status: {status}; User: {username}",
            "severity": "Informational",
            "recommendation": "Review if the process is unfamiliar."
        })

    # 3. Network records
    for port in open_ports:
        records.append({
            "scan_time": scan_time,
            "category": "Network",
            "item": f"TCP port {port['port']} ({port['service']})",
            "description": (
                "TCP connection accepted on localhost "
                "(127.0.0.1). Remote exposure is not "
                "determined by this check."
            ),
            "severity": "Informational",
            "recommendation": (
                "Verify that the service is required and "
                "check its listening interfaces and firewall rules."
            )
        })

    # 4. Software records
    for app in software or []:
        records.append({
            "scan_time": scan_time,
            "category": "Software",
            "item": app["name"],
            "description": (
                f"Version: {app['version']}; "
                f"Publisher: {app['publisher']}"
            ),
            "severity": "Informational",
            "recommendation": (
                "Review whether this software is required "
                "and keep it updated."
            )
        })

    # 5. File and Configuration records
    for item in file_config or []:
        source = item.get("source", "File/Config")
        name = item.get("name", "Unknown")
        path = item.get("path", "Unavailable")
        details = item.get("details", "")
        size = item.get("size_bytes")
        modified = item.get("last_modified", "Unavailable")

        records.append({
            "scan_time": scan_time,
            "category": "File/Config",
            "item": f"{source}: {name}",
            "description": (
                f"Path: {path}; "
                f"Details: {details}; "
                f"Size: {size} bytes; "
                f"Last Modified: {modified}"
            ),
            "severity": "Informational",
            "recommendation": (
                "Review configuration and startup entries. "
                "Investigate unfamiliar entries manually."
            )
        })

    return records
