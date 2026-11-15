
import os
from pathlib import Path
from datetime import datetime


def get_file_metadata(path):
    """Collect basic metadata for a file or directory."""

    try:
        stat = path.stat()

        return {
            "size_bytes": stat.st_size if path.is_file() else 0,
            "last_modified": datetime.fromtimestamp(
                stat.st_mtime
            ).astimezone().isoformat(timespec="seconds")
        }

    except (OSError, PermissionError):
        return {
            "size_bytes": None,
            "last_modified": "Unavailable"
        }


def scan_config_files():
    """Inventory selected Windows configuration files."""

    findings = []

    windows_dir = Path(
        os.environ.get("SystemRoot", r"C:\Windows")
    )

    config_files = [
        windows_dir / "System32" / "drivers" / "etc" / "hosts",
        windows_dir / "win.ini",
        windows_dir / "system.ini"
    ]

    for file_path in config_files:

        if not file_path.is_file():
            continue

        metadata = get_file_metadata(file_path)
        details = "Configuration file found."

        # Read active mappings from the Windows hosts file.
        if file_path.name.lower() == "hosts":

            mappings = []

            try:
                with file_path.open(
                    "r",
                    encoding="utf-8",
                    errors="replace"
                ) as file:

                    for line in file:
                        line = line.split("#", 1)[0].strip()

                        if not line:
                            continue

                        parts = line.split()

                        if len(parts) >= 2:
                            mappings.append(
                                f"{parts[0]} -> "
                                f"{', '.join(parts[1:])}"
                            )

                details = (
                    f"Active host mappings found: "
                    f"{len(mappings)}. "
                )

                if mappings:
                    details += "Mappings: " + "; ".join(mappings[:10])

                    if len(mappings) > 10:
                        details += (
                            f"; and {len(mappings) - 10} more"
                        )
                else:
                    details += "No active mappings found."

            except OSError:
                details = "Unable to read hosts file."

        findings.append({
            "source": "Configuration File",
            "name": file_path.name,
            "path": str(file_path),
            "details": details,
            **metadata
        })

    return findings


def scan_startup_folders():
    """Inventory entries in standard Windows startup folders."""

    findings = []

    startup_locations = [
        (
            "User Startup Folder",
            os.environ.get("APPDATA"),
            "Microsoft/Windows/Start Menu/Programs/Startup"
        ),
        (
            "Common Startup Folder",
            os.environ.get("ProgramData"),
            "Microsoft/Windows/Start Menu/Programs/Startup"
        )
    ]

    for label, base_directory, relative_path in startup_locations:

        if not base_directory:
            continue

        startup_path = Path(base_directory) / relative_path

        if not startup_path.is_dir():
            continue

        try:
            entries = sorted(
                startup_path.iterdir(),
                key=lambda item: item.name.lower()
            )

        except OSError:
            findings.append({
                "source": label,
                "name": "Access unavailable",
                "path": str(startup_path),
                "details": "Unable to inspect this startup folder.",
                "size_bytes": None,
                "last_modified": "Unavailable"
            })

            continue

        if not entries:
            findings.append({
                "source": label,
                "name": "Empty startup folder",
                "path": str(startup_path),
                "details": "No startup entries found.",
                "size_bytes": 0,
                "last_modified": "Unavailable"
            })

        for entry in entries:

            metadata = get_file_metadata(entry)

            entry_type = (
                "Directory" if entry.is_dir() else "File"
            )

            findings.append({
                "source": label,
                "name": entry.name,
                "path": str(entry),
                "details": f"Startup entry type: {entry_type}.",
                **metadata
            })

    return findings


def get_file_config_items():
    """
    Collect selected Windows configuration file metadata
    and startup folder inventory.
    """

    if os.name != "nt":
        return []

    findings = []

    findings.extend(scan_config_files())
    findings.extend(scan_startup_folders())

    return findings


if __name__ == "__main__":

    print("=" * 50)
    print("FILE & CONFIGURATION SCANNER")
    print("=" * 50)

    results = get_file_config_items()

    for item in results:
        print(f"\nSource: {item['source']}")
        print(f"Name: {item['name']}")
        print(f"Path: {item['path']}")
        print(f"Details: {item['details']}")
        print(f"Size: {item['size_bytes']} bytes")
        print(f"Last Modified: {item['last_modified']}")

    print("\n" + "=" * 50)
    print(f"Total items collected: {len(results)}")
    print("File and configuration scan completed.")
