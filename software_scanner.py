
import winreg


REGISTRY_LOCATIONS = [
    (
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    ),
    (
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    ),
    (
        winreg.HKEY_CURRENT_USER,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
]


def get_installed_software(limit=15):
    """Read installed software information from Windows Registry."""

    applications = {}

    for root, path in REGISTRY_LOCATIONS:
        try:
            with winreg.OpenKey(root, path) as registry_key:
                count = winreg.QueryInfoKey(registry_key)[0]

                for index in range(count):
                    try:
                        subkey_name = winreg.EnumKey(
                            registry_key, index
                        )

                        with winreg.OpenKey(
                            registry_key, subkey_name
                        ) as app_key:

                            try:
                                name = winreg.QueryValueEx(
                                    app_key, "DisplayName"
                                )[0]
                            except OSError:
                                continue

                            if not isinstance(name, str) or not name.strip():
                                continue

                            try:
                                version = winreg.QueryValueEx(
                                    app_key, "DisplayVersion"
                                )[0]
                            except OSError:
                                version = "Unknown"

                            try:
                                publisher = winreg.QueryValueEx(
                                    app_key, "Publisher"
                                )[0]
                            except OSError:
                                publisher = "Unknown"

                            key = name.strip().casefold()

                            applications.setdefault(key, {
                                "name": name.strip(),
                                "version": str(version),
                                "publisher": str(publisher)
                            })

                    except OSError:
                        continue

        except OSError:
            continue

    results = sorted(
        applications.values(),
        key=lambda app: app["name"].casefold()
    )

    return results[:limit]
