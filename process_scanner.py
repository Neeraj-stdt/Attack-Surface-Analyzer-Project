
import psutil


def get_processes(limit=15):
    """Collect information about currently running processes."""

    processes = []

    for process in psutil.process_iter(
        ["pid", "name", "username", "status"]
    ):
        try:
            processes.append(process.info)

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    return processes[:limit]
