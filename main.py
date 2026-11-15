
from database import init_db, save_scan
from collections import Counter

from modules.system_scanner import get_system_info
from modules.process_scanner import get_processes
from modules.port_scanner import scan_ports
from modules.software_scanner import get_installed_software
from modules.result_formatter import build_records
from modules.risk_analyzer import apply_risk_analysis


def main():
    # Initialize the database
    init_db()

    print("=" * 50)
    print("          ATTACK SURFACE ANALYZER")
    print("=" * 50)

    # Module 1: System Information
    print("\n[1] SYSTEM INFORMATION")

    system_info = get_system_info()

    for key, value in system_info.items():
        print(f"{key}: {value}")

    # Module 2: Process Analysis
    print("\n[2] RUNNING PROCESSES")

    processes = get_processes()

    for process in processes:
        print(
            f"PID: {process.get('pid')} | "
            f"Name: {process.get('name')} | "
            f"User: {process.get('username')} | "
            f"Status: {process.get('status')}"
        )

    print(f"\nProcesses collected: {len(processes)}")

    # Module 3: Network and Port Analysis
    print("\n[3] NETWORK & PORT ANALYSIS")
    print("Scanning localhost for common TCP ports...\n")

    open_ports = scan_ports()

    if open_ports:
        for item in open_ports:
            print(
                f"Port: {item['port']} | "
                f"Service: {item['service']} | "
                f"Status: {item['status']}"
            )
    else:
        print("No selected TCP ports were found open.")

    # Module 4: Software Analysis
    print("\n[4] INSTALLED SOFTWARE")

    software = get_installed_software(limit=15)

    for app in software:
        print(
            f"Name: {app['name']} | "
            f"Version: {app['version']} | "
            f"Publisher: {app['publisher']}"
        )

    print(f"\nApplications collected: {len(software)}")

    # Module 5: Standardize Results
    print("\n[5] STANDARDIZED SCAN RECORDS")

    records = build_records(
        system_info,
        processes,
        open_ports,
        software
    )

    print(f"Total records prepared: {len(records)}")

    # Module 6: Risk Analysis
    print("\n[6] RISK ANALYSIS")

    records = apply_risk_analysis(records)

    severity_counts = Counter(
        record["severity"] for record in records
    )

    print("\nRisk Summary:")

    for level in ["High", "Medium", "Low", "Informational"]:
        print(f"{level}: {severity_counts.get(level, 0)}")

    # Module 7: Save scan results to SQLite
    print("\n[7] DATABASE STORAGE")

    scan_id = save_scan(
        records,
        hostname=system_info.get("Hostname")
    )

    print(f"Scan saved successfully! Scan ID: {scan_id}")
    print(f"Findings saved: {len(records)}")

    # Display sample findings
    print("\nSAMPLE FINDINGS")

    for record in records[:10]:
        print(
            f"[{record['category']}] "
            f"{record['item']} | "
            f"Risk: {record['severity']}"
        )

    print("\n" + "=" * 50)
    print("All scans completed successfully!")
    print("Results saved to the SQLite database.")
    print("=" * 50)


if __name__ == "__main__":
    main()
