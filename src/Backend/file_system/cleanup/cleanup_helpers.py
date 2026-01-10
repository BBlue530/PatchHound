import os
import stat

def remove_stubborn_backup(func, path, excinfo):
    os.chmod(path, stat.S_IWRITE)
    func(path)