"""
Identification of the machine where the experiments are run.

The assignment requires recording the CPU model and the number of cores
alongside the results, so that the measurements are interpretable and
reproducible.
"""

import os
import platform
import subprocess
import sys

__all__ = ["cpu_model", "system_info"]


def cpu_model() -> str:
    """Commercial processor name, falling back to `platform.processor()`."""
    try:
        if sys.platform == "win32":
            import winreg

            key_path = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                return str(winreg.QueryValueEx(key, "ProcessorNameString")[0]).strip()
        if sys.platform == "darwin":
            output = subprocess.check_output(
                ["sysctl", "-n", "machdep.cpu.brand_string"], text=True
            )
            return output.strip()
        with open("/proc/cpuinfo", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:  # noqa: BLE001 - identification must never abort the measurement
        pass
    return platform.processor() or "desconocido"


def system_info(physical_cores: int | None = None) -> dict:
    """Dictionary with the run environment, embedded in every result."""
    return {
        "cpu_model": cpu_model(),
        "logical_cores": os.cpu_count(),
        "physical_cores": physical_cores,
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
    }
