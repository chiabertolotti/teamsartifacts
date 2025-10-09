# ------------------------------------------------------------------------------
# This code extracts IndexedDB records with object_store_name "replychains"
# and saves them to a JSON file.
# ------------------------------------------------------------------------------

import pathlib
import json
from dfindexeddb.indexeddb.chromium import record
import os

def replychains_extraction(path, output_json):
    """
    Extracts all IndexedDB records with the same database_id as the record
    with object_store_name == "replychains" and with index_id=1.
    Works on both single files and LevelDB folders.
    Skips invalid files (e.g. $I30, desktop.ini, etc).
    """
    path = pathlib.Path(path)
    # Function to filter only valid LevelDB files
    def is_leveldb_file(f):
        name = f.name
        return (
            name.startswith("MANIFEST") or
            name == "CURRENT" or
            name.endswith(".ldb") or
            name.endswith(".log")
        )
    # Choose the right reader
    if path.is_dir():
        # Filter only valid files
        files = [f for f in path.iterdir() if f.is_file() and is_leveldb_file(f)]
        def all_records():
            for f in files:
                try:
                    yield from record.IndexedDBRecord.FromFile(f)
                except Exception as e:
                    print(f"[WARN] Skipped file {f}: {e}")
        record_iter = all_records()
    else:
        record_iter = record.IndexedDBRecord.FromFile(path)
    # First step: find all database_id for "replychains" and save the records
    database_ids = set()
    records = []
    def save_nameskey_records(record_iter):
        for rec in record_iter:
            key = rec.key
            if hasattr(key, "object_store_name") and getattr(key, "object_store_name", None) == "replychains":
                kp = getattr(key, "key_prefix", None)
                if kp and kp.object_store_id == 0 and kp.index_id == 0:
                    database_ids.add(kp.database_id)

    if path.is_dir():
        for f in files:
            try:
                save_nameskey_records(record.IndexedDBRecord.FromFile(f))
            except Exception as e:
                print(f"[WARN] Skipped file {f}: {e}")
    else:
        save_nameskey_records(record.IndexedDBRecord.FromFile(path))

    if not database_ids:
        print("No database_id found for object_store_name='replychains'")
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(records, f, ensure_ascii=False, indent=2, sort_keys=True)
        print(f"Saved {len(records)} records to {output_json}")
        return

    # Second step: extract all desired records for each found database_id
    def save_datakey_records(record_iter, path_str):
        for rec in record_iter:
            kp = getattr(rec.key, "key_prefix", None)
            if kp and kp.database_id in database_ids and kp.index_id == 1:
                try:
                    records.append({
                        "offset": rec.offset,
                        "database_id": kp.database_id,
                        "object_store_id": kp.object_store_id,
                        "index_id": kp.index_id,
                        "key": to_serializable(rec.key),
                        "value": to_serializable(rec.value)
                    })
                except Exception as e:
                    print(f"Record serialization error: {e}")

    if path.is_dir():
        for f in files:
            try:
                save_datakey_records(record.IndexedDBRecord.FromFile(f), str(f))
            except Exception as e:
                print(f"[WARN] Skipped file {f}: {e}")
    else:
        save_datakey_records(record.IndexedDBRecord.FromFile(path), str(path))
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2, sort_keys=True)
    print(f"Saved {len(records)} records to {output_json}")

def to_serializable(obj):
    """
    Recursively serializes complex objects into JSON-friendly dicts,
    adding '__type__' where appropriate.
    """
    import enum
    from dataclasses import is_dataclass, asdict
    if is_dataclass(obj):
        result = {k: to_serializable(v) for k, v in asdict(obj).items()}
        result['__type__'] = obj.__class__.__name__
        return result
    elif isinstance(obj, enum.Enum):
        return obj.name
    elif isinstance(obj, dict):
        return {to_serializable(k): to_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple, set)):
        return [to_serializable(i) for i in obj]
    elif hasattr(obj, '__dict__'):
        result = {k: to_serializable(v) for k, v in obj.__dict__.items() if not k.startswith('_')}
        result['__type__'] = obj.__class__.__name__
        return result
    elif isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    else:
        return str(obj)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Extract IndexedDB replychains records")
    parser.add_argument("input_path", help="IndexedDB/LevelDB file or folder")
    parser.add_argument("output_json", help="Output JSON file")
    args = parser.parse_args()
    replychains_extraction(args.input_path, args.output_json)