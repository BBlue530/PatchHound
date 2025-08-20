import os
import shutil
import subprocess
import sys
import urllib.request
from core.variables import GRYPE_VERSION, COSIGN_VERSION

local_bin = os.path.expanduser("~/.local/bin")

def make_local_bin():
    local_bin = os.path.expanduser("~/.local/bin")
    os.makedirs(local_bin, exist_ok=True)
    print(f"[+] Directory exists: {local_bin}")

    # Checks local/bin
    if local_bin not in os.environ.get("PATH", "").split(os.pathsep):
        print(f"[!] Warning: {local_bin} is not in PATH")

def install_grype():
    print(f"[~] Installing Grype version {GRYPE_VERSION}...")
    install_script_url = f"https://raw.githubusercontent.com/anchore/grype/v{GRYPE_VERSION}/install.sh"
    subprocess.run(
        f"curl -sSfL {install_script_url} | sh -s -- -b {local_bin} v{GRYPE_VERSION}",
        shell=True,
        check=True
    )
    print("[+] Grype is installed")

def install_cosign():
    print(f"[~] Installing Cosign version {COSIGN_VERSION}...")

    arch_map = {
        "x86_64": "amd64",
        "aarch64": "arm64",
        "armv7l": "arm"
    }
    uname_arch = os.uname().machine
    arch = arch_map.get(uname_arch)
    if not arch:
        print(f"[!] Unsupported arch for Cosign: {uname_arch}")
        sys.exit(1)

    cosign_url = f"https://github.com/sigstore/cosign/releases/download/v{COSIGN_VERSION}/cosign-linux-{arch}"
    cosign_path = os.path.join(local_bin, "cosign")

    urllib.request.urlretrieve(cosign_url, cosign_path)
    os.chmod(cosign_path, 0o755)

    print("[+] Cosign is installed")

def version_check(tool, version_arg, env=None):
    result = subprocess.run([tool, version_arg], capture_output=True, text=True, env=env)
    print(result.stdout)

def install_tools():
    make_local_bin()

    env = os.environ.copy()
    env["PATH"] = local_bin + os.pathsep + env.get("PATH", "")

    if not tool_exists("grype"):
        install_grype()
        version_check("grype", "--version")
    else:
        version_check("grype", "--version")
        print("[+] Grype is installed")

    if not tool_exists("cosign"):
        install_cosign()
        version_check("cosign", "version", env)
    else:
        version_check("cosign", "version", env)
        print("[+] Cosign is installed")

def tool_exists(tool_name):
    return shutil.which(tool_name) is not None