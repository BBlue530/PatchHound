import os
import shutil
import subprocess
import sys
import urllib.request

local_bin = os.path.expanduser("~/.local/bin")

def make_local_bin():
    local_bin = os.path.expanduser("~/.local/bin")
    os.makedirs(local_bin, exist_ok=True)
    print(f"[+] Directory exists: {local_bin}")

    # Checks local/bin
    if local_bin not in os.environ.get("PATH", "").split(os.pathsep):
        print(f"[!] Warning: {local_bin} is not in PATH")

def install_grype():
    print("[~] Installing Grype...")
    subprocess.run(
        f"curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b {local_bin}",
        shell=True,
        check=True
    )
    print("[+] Grype is installed")

def install_cosign():
    print("[~] Installing Cosign...")

    cosign_url = f"https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-{arch}"
    cosign_path = os.path.join(local_bin, "cosign")
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

    urllib.request.urlretrieve(cosign_url, cosign_path)
    os.chmod(cosign_path, 0o755)

    print("[+] Cosign is installed")

def install_tools():
    make_local_bin()
    if not tool_exists("grype"):
        install_grype()
    else:
        print("[+] Grype is installed")

    if not tool_exists("cosign"):
        install_cosign()
    else:
        print("[+] Cosign is installed")

def tool_exists(tool_name):
    return shutil.which(tool_name) is not None