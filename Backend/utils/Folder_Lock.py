from filelock import FileLock
import os

def repo_lock(repo_dir, func, *args, **kwargs):

    lock_path = os.path.join(repo_dir, ".lock")
    with FileLock(lock_path):
        print(f"[~] Folder locked: {repo_dir}")
        result = func(*args, **kwargs)
        print(f"[+] Folder unlocked: {repo_dir}")
        return result