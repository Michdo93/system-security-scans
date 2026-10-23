#!/usr/bin/env python3
"""Run rkhunter, ClamAV and chkrootkit and email detected findings."""
import os
import smtplib
import socket
import subprocess
from email.mime.text import MIMEText
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


def email(subject, body):
    username, password = os.getenv('SMTP_USERNAME'), os.getenv('SMTP_PASSWORD')
    sender = os.getenv('MAIL_FROM', username or '')
    recipient = os.getenv('MAIL_TO', '')
    if not all((username, password, sender, recipient)):
        print('SMTP is not configured; skipping email alert.')
        return
    msg = MIMEText(body)
    msg['Subject'], msg['From'], msg['To'] = subject, sender, recipient
    with smtplib.SMTP(os.getenv('SMTP_HOST', 'smtp.gmail.com'), int(os.getenv('SMTP_PORT', '587')), timeout=30) as smtp:
        smtp.starttls()
        smtp.login(username, password)
        smtp.send_message(msg)


def run(command):
    return subprocess.run(command, text=True, capture_output=True, check=False)


def main():
    host = socket.gethostname()
    rkhunter_update = run(['rkhunter', '--update'])
    if rkhunter_update.returncode:
        print('rkhunter update failed:', rkhunter_update.stderr)
    result = run(['rkhunter', '--check', '--sk'])
    print(result.stdout)
    if result.returncode:
        email(f'RKHunter warnings on {host}', result.stdout + result.stderr)

    clamlog = Path(os.getenv('CLAMAV_LOG', '/var/log/clamav_infected.log'))
    clamlog.parent.mkdir(parents=True, exist_ok=True)
    cmd = ['clamscan', '-ir', '/', '--log=' + str(clamlog), '--exclude=/opt/yara-patterns', '--exclude=/opt/yara-4.4.0', '--exclude=/opt/thor-lite/custom-signatures', '--exclude=/opt/thor-lite/signatures', '--exclude-dir=^/sys', '--exclude-dir=^/dev', '--exclude-dir=^/proc']
    clam = run(cmd)
    if clam.returncode == 1:
        email(f'ClamAV findings on {host}', clam.stdout + clam.stderr)
    elif clam.returncode > 1:
        print('ClamAV scan error:', clam.stdout, clam.stderr)

    chk = run(['chkrootkit'])
    Path(os.getenv('CHKROOTKIT_LOG', '/var/log/chkrootkit.log')).write_text(chk.stdout + chk.stderr, encoding='utf-8')
    if 'INFECTED' in chk.stdout:
        email(f'chkrootkit findings on {host}', chk.stdout)
    if chk.returncode:
        print('chkrootkit returned an error; inspect its log.')


if __name__ == '__main__':
    main()
