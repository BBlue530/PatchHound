import os

def verify_file_exists(files):
    files_missing = []
    all_files_exist = True

    for file in files:
        if not os.path.exists(file):
            files_missing.append(file)
    
    if files_missing:
        all_files_exist = False
    
    return all_files_exist, files_missing