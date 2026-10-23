#!/usr/bin/env python3
"""YARA scan with log output and optional email alerts for matches."""
import logging
import os
import smtplib
import socket
from email.mime.text import MIMEText
from pathlib import Path

import yara
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(filename=os.getenv('YARA_LOG', '/var/log/yara_scan.log'), level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')


def excluded(path, entries):
    return any(path == item or item in path.parents for item in entries)


def send_email(subject, body):
    username, password = os.getenv('SMTP_USERNAME'), os.getenv('SMTP_PASSWORD')
    sender = os.getenv('MAIL_FROM', username or '')
    recipient = os.getenv('MAIL_TO', '')
    if not all((username, password, sender, recipient)):
        logging.warning('SMTP incomplete; email alert skipped')
        return
    msg = MIMEText(body)
    msg['Subject'], msg['From'], msg['To'] = subject, sender, recipient
    with smtplib.SMTP(os.getenv('SMTP_HOST', 'smtp.gmail.com'), int(os.getenv('SMTP_PORT', '587')), timeout=30) as smtp:
        smtp.starttls()
        smtp.login(username, password)
        smtp.send_message(msg)


def main():
    rules_path = Path(os.getenv('YARA_RULES', '/opt/yara-patterns/all-hfu.yar'))
    if not rules_path.is_file():
        raise SystemExit(f'YARA rules file not found: {rules_path}')
    rules = yara.compile(filepath=str(rules_path))
    target = Path(os.getenv('SCAN_ROOT', '/'))
    excluded_paths = [Path(x.strip()) for x in os.getenv('YARA_EXCLUDED_PATHS', '').split(',') if x.strip()]
    extensions = {x.strip().lower() for x in os.getenv('YARA_EXCLUDED_EXTENSIONS', '').split(',') if x.strip()}
    matches = []
    for root, dirs, files in os.walk(target, onerror=lambda exc: logging.warning('Traversal error: %s', exc)):
        current = Path(root)
        if excluded(current, excluded_paths):
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if not excluded(current / d, excluded_paths)]
        for filename in files:
            path = current / filename
            if path.suffix.lower() in extensions:
                continue
            try:
                for match in rules.match(str(path)):
                    line = f'Gefunden: {match.rule} in {path}'
                    matches.append(line)
                    logging.warning(line)
            except (yara.Error, OSError) as exc:
                logging.error('Cannot scan %s: %s', path, exc)
    if matches:
        send_email(f'Warnings on {socket.gethostname()}: YARA Scan Results', '\n'.join(matches))
        print('\n'.join(matches))
    else:
        print('YARA scan complete; no matches found.')


if __name__ == '__main__':
    main()
