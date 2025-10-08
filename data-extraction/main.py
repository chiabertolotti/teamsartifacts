#!/usr/bin/env python3
import os
import subprocess
import shutil

REPO_URL = "https://github.com/google/dfindexeddb.git"
REPO_NAME = "dfindexeddb"

if not os.path.exists(REPO_NAME):
    subprocess.run(["git", "clone", REPO_URL])

os.chdir(REPO_NAME)
subprocess.run(["sudo", "apt", "update"])
subprocess.run(["sudo", "apt", "install", "libsnappy-dev"])
subprocess.run(["python3", "-m", "venv", "venv"])
venv_python = os.path.join("venv", "bin", "python")
subprocess.run([venv_python, "-m", "pip", "install", "."])

# Move the extraction scripts to the dfindexeddb directory
parent_dir = os.path.dirname(os.getcwd())
script1_src = os.path.join(parent_dir, "replychains-extraction.py")
script2_src = os.path.join(parent_dir, "conversations-extraction.py")
script3_src = os.path.join(parent_dir, "people-extraction.py")

if os.path.exists(script1_src):
    shutil.copy2(script1_src, ".")
if os.path.exists(script2_src):
    shutil.copy2(script2_src, ".")
if os.path.exists(script3_src):
    shutil.copy2(script3_src, ".")
# Sobstituting the path to your IndexedDB LevelDB folder of Microsoft Teams
leveldb_path = "/mnt/c/Users/*/MSTeams_8wekyb3d8bbwe/LocalCache/Microsoft/MSTeams/EBWebView/WV2Profile_tfw/IndexedDB/https_teams.microsoft.com_0.indexeddb.leveldb/"
subprocess.run([
    venv_python,
    "replychains-extraction.py",
    leveldb_path,
    "output_replychains.json"
])
subprocess.run([
    venv_python,
    "conversations-extraction.py",
    leveldb_path,
    "output_conversations.json"
])
subprocess.run([
    venv_python,
    "people-extraction.py",
    leveldb_path,
    "output_people.json"
])