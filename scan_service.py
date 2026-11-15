
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, current_thread
from collections import Counter

from database import init_db, save_scan

from modules.system_scanner import get_system_info
from modules.process_scanner import get_processes
from modules.port_scanner import scan_ports
from modules.software_scanner import get_installed_software
from modules.file_config_scanner import get_file_config_items

from modules.result_formatter import build_records
from modules.risk_analyzer import apply_risk_analysis


def run_scan():
    """Run all scanner modules concurrently and save findings."""

    init_db()

    results = {}
    errors = {}

    # Synchronization lock for shared dictionaries
    results_lock = Lock()

    # Five independent scanning tasks
    tasks = {
        "system_info": get_system_info,
        "processes": get_processes,
        "open_ports": scan_ports,
        "software": lambda: get_installed_software(limit=15),
        "file_config": get_file_config_items
    }

    def execute_scanner(name, scanner_function):
        thread_name = current_thread().name

        print(f"[START] {name} | Thread: {thread_name}")

        try:
            output = scanner_function()

            # Protect shared results using synchronization
            with results_lock:
                results[name] = output

            print(f"[DONE] {name}")

        except Exception as error:
            with results_lock:
                errors[name] = str(error)

            print(f"[ERROR] {name}: {error}")

    print("\nStarting concurrent scanning...\n")

    # Execute all scanners using a thread pool
    with ThreadPoolExecutor(
        max_workers=5,
        thread_name_prefix="ASA-Scanner"
    ) as executor:

        futures = [
            executor.submit(execute_scanner, name, function)
            for name, function in tasks.items()
        ]

        for future in as_completed(futures):
            future.result()

    # Retrieve results after all tasks finish
    system_info = results.get("system_info", {})
    processes = results.get("processes", [])
    open_ports = results.get("open_ports", [])
    software = results.get("software", [])
    file_config = results.get("file_config", [])

    # Standardize all scanner findings
    records = build_records(
        system_info,
        processes,
        open_ports,
        software,
        file_config
    )

    # Apply risk analysis
    records = apply_risk_analysis(records)

    # Save findings to SQLite
    scan_id = save_scan(
        records,
        hostname=system_info.get("Hostname")
    )

    # Calculate severity counts
    severity_counts = Counter(
        record["severity"] for record in records
    )

    risk_summary = {
        level: severity_counts.get(level, 0)
        for level in ["High", "Medium", "Low", "Informational"]
    }

    # Return scan summary
    return {
        "scan_id": scan_id,
        "scan_time": records[0]["scan_time"] if records else None,
        "hostname": system_info.get("Hostname"),
        "total_findings": len(records),
        "risk_summary": risk_summary,

        "component_counts": {
            "processes": len(processes),
            "open_ports": len(open_ports),
            "software": len(software),
            "file_config": len(file_config)
        },

        "scanner_errors": errors,
        "findings": records
    }
