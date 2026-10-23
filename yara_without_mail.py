#!/usr/bin/env python3
"""YARA scan without email notifications."""
import os
from pathlib import Path
import yara
from dotenv import load_dotenv

load_dotenv()


def main():
    rules_path = Path(os.getenv('YARA_RULES', '/opt/yara-patterns/all-hfu.yar'))
    rules = yara.compile(filepath=str(rules_path))
    target = Path(os.getenv('SCAN_ROOT', '/'))
    excluded = [Path(x.strip()) for x in os.getenv('YARA_EXCLUDED_PATHS', '').split(',') if x.strip()]
    extensions = {x.strip().lower() for x in os.getenv('YARA_EXCLUDED_EXTENSIONS', '').split(',') if x.strip()}
    for root, dirs, files in os.walk(target):
        current = Path(root)
        if any(current == p or p in current.parents for p in excluded):
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if not any(current / d == p or p in (current / d).parents for p in excluded)]
        for name in files:
            path = current / name
            if path.suffix.lower() in extensions:
                continue
            try:
                for match in rules.match(str(path)):
                    print(f'Gefunden: {match.rule} in {path}')
            except (yara.Error, OSError) as exc:
                print(f'Fehler beim Scannen von {path}: {exc}')


if __name__ == '__main__':
    main()
