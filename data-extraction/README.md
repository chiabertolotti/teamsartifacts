# IndexedDB Data Extraction 

## Overview

The `main.py` script automates the process of:

1. Setting up the dfindexeddb environment.
2. Extracting conversation data, replychains, and people information from Microsoft Teams IndexedDB files.
3. Generating JSON output files with the extracted data.

## What the Script Does

### Setup Phase

- Clones the [Google dfindexeddb repository](https://github.com/google/dfindexeddb.git).
- Updates the system packages (`sudo apt update`).
- Installs required system dependencies (`libsnappy-dev`).
- Creates a Python virtual environment.
- Installs the dfindexeddb package in the virtual environment.

### Data Extraction Phase

- Copies the extraction scripts (`replychains-extraction.py`, `conversations-extraction.py`, `people-extraction.py`) to the dfindexeddb directory.
- Runs three extraction processes:
  - **Replychains**: Extracts conversation reply chains and saves to `output_replychains.json`.
  - **Conversations**: Extracts conversation data and saves to `output_conversations.json`.
  - **People**: Extracts people/contact information and saves to `output_people.json`.

## Prerequisites

- Python 3.x
- Git
- Ubuntu/Debian-based system (or WSL on Windows)
- Access to Microsoft Teams IndexedDB files

## Usage

1. Place the extraction scripts in the same directory as `main.py`:
   
   - `replychains-extraction.py`
   - `conversations-extraction.py`
   - `people-extraction.py`

2. Update the `leveldb_path` variable in `main.py` to point to your IndexedDB directory:
   
   ```python
   leveldb_path = "/path/to/your/IndexedDB/folder/of/Microsoft/Teams"
   ```

3. Make the script executable and run it:
   
   ```bash
   chmod +x main.py
   python main.py
   ```

## Default Configuration

The script is currently configured to extract data from:

```
/mnt/c/Users/*/MSTeams_8wekyb3d8bbwe/LocalCache/Microsoft/MSTeams/EBWebView/WV2Profile_tfw/IndexedDB/https_teams.microsoft.com_0.indexeddb.leveldb/
```

This path corresponds to a typical Microsoft Teams IndexedDB location in WSL (Windows Subsystem for Linux).

## Output Files

After successful execution, you'll find three JSON files in the `dfindexeddb` directory:

- `output_replychains.json` - Contains extracted reply chain data.
- `output_conversations.json` - Contains extracted conversation data.
- `output_people.json` - Contains extracted people/contact data.
