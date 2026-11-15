
import platform
import socket
import psutil


def get_system_info():
    memory = psutil.virtual_memory()

    info = {
        "Hostname": socket.gethostname(),
        "Operating System": platform.system(),
        "OS Version": platform.version(),
        "Architecture": platform.machine(),
        "CPU Cores": psutil.cpu_count(),
        "Total RAM (GB)": round(memory.total / (1024 ** 3), 2),
        "Available RAM (GB)": round(memory.available / (1024 ** 3), 2),
        "RAM Usage (%)": memory.percent
    }

    return info
