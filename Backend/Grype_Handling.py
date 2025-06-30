import subprocess
import shutil
from pathlib import Path

def clear_and_update_grype_cache():
    print("[~] Warming up grype DB (may take a few seconds)...")
    cache_path = Path.home() / ".cache" / "grype"
    if cache_path.exists():
        print("[~] Clearing Grype cache directory...")
        try:
            shutil.rmtree(cache_path, ignore_errors=True)
            print("[✓] Grype cache cleared.")
        except Exception as e:
            print(f"[!] Failed to clear cache: {e}")
    else:
        print("[!] Grype cache directory does not exist.")
    try:
        subprocess.run(["grype", "db", "update"], check=True)
        print("[+] Grype database updated")
    except subprocess.CalledProcessError as e:
        print(f"[!] Grype DB update failed: {e.stderr}")