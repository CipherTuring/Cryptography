"""
Identification of the machine where the experiments are run.

The assignment requires the same computer and the same experimental
conditions for all measurements, so the processor and the interpreter
are recorded alongside every result. Without them the numbers cannot be
compared against anything or reproduced later.
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
    except Exception:  # noqa: BLE001 - identification must never abort a run
        pass
    return platform.processor() or "unknown"


def system_info() -> dict:
    """Dictionary describing the run environment, embedded in every result."""
    return {
        "cpu_model": cpu_model(),
        "logical_cores": os.cpu_count(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
    }
