# System Security Scans

Kleine Sammlung von Linux-Scannern für einen Proxmox/Debian-Host. Enthalten sind ein kombinierter Scan mit rkhunter, ClamAV und chkrootkit sowie YARA-Scans mit optionaler E-Mail-Benachrichtigung.

> **Sicherheit:** Zugangsdaten gehören ausschließlich in eine lokale `.env`-Datei oder einen Secret Store. Die im Ursprungstext enthaltenen SMTP-Zugangsdaten wurden nicht übernommen. Falls sie noch gültig sind, bitte beim Mailanbieter widerrufen und neu erzeugen.

## Inhalt

- `scan.py` – rkhunter aktualisieren und prüfen, ClamAV-Scan ausführen, chkrootkit ausführen und bei Funden mailen.
- `yara_scan.py` – YARA-Scan mit Logdatei und optionaler Mail bei Treffern.
- `yara_without_mail.py` – einfacher YARA-Scan ohne Mail.
- `.env.example` – kommentierte Vorlage für Pfade, Ausschlüsse und Mailparameter.
- `requirements.txt` – Python-Abhängigkeiten für YARA und `.env`-Konfiguration.

## Unterstützte Umgebung

Debian/Proxmox VE mit Python 3.10 oder neuer. Die Scanner laufen typischerweise als `root`, da sie Systemdateien lesen und Logs unter `/var/log` schreiben. Ein vollständiger Scan über `/` kann lange dauern und viel I/O erzeugen.

## Installation

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip clamav clamav-daemon rkhunter chkrootkit aide
sudo install -d -m 0755 /opt/system-security-scans
```

Repo-Inhalt nach `/opt/system-security-scans` kopieren bzw. dort klonen. Anschließend virtuelle Umgebung erstellen:

```bash
cd /opt/system-security-scans
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
```

Auf Debian kann `yara-python` für die Python-/Compiler-Version eventuell nicht als Wheel verfügbar sein. Dann zusätzlich Compiler und YARA-Entwicklungsdateien installieren und erneut `pip install -r requirements.txt` ausführen:

```bash
sudo apt install -y build-essential libyara-dev
```

Alternativ kann `python3-yara` aus den Debian-Paketquellen verwendet werden. In diesem Fall muss das System-Python genutzt werden und die Python-Abhängigkeiten sind entsprechend anzupassen.

### Signaturen und YARA-Regeln

Die Skripte installieren keine Signaturen. Stelle eine vertrauenswürdige YARA-Regeldatei bereit und aktualisiere diese nach dem Verfahren des Regelanbieters. Standardpfad ist `/opt/yara-patterns/all-hfu.yar`. Prüfe, ob die Regeln externe Dateien einbinden; diese müssen ebenfalls vorhanden sein.

ClamAV-Signaturen initialisieren/aktualisieren:

```bash
sudo systemctl enable --now clamav-freshclam
sudo freshclam
```

Auf manchen Debian-Versionen blockiert der laufende `clamav-freshclam`-Dienst einen manuellen `freshclam`-Aufruf. Dann den Dienst die Aktualisierung durchführen lassen.

## Konfiguration

```bash
cd /opt/system-security-scans
cp .env.example .env
chmod 600 .env
editor .env
```

Wichtige Werte:

- `YARA_RULES`: YARA-Regeldatei.
- `SCAN_ROOT`: zu scannender Startpfad, standardmäßig `/`.
- `YARA_EXCLUDED_PATHS`: kommagetrennte Pfade, die beim YARA-Lauf übersprungen werden.
- `YARA_EXCLUDED_EXTENSIONS`: kommagetrennte Dateiendungen.
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `MAIL_FROM`, `MAIL_TO`: SMTP-Relay und Empfänger. Für Gmail ein App-Passwort und aktiviertes 2-Faktor-Konto verwenden, nicht das normale Kontopasswort. Ohne vollständige SMTP-Konfiguration schreibt `yara_scan.py` nur ins Log und sendet keine Mail.
- `CLAMAV_LOG`, `CHKROOTKIT_LOG`, `AIDE_CONFIG`: Pfade der Scanner-Ausgaben und AIDE-Konfiguration.

`.env` wird durch `.gitignore` ausgeschlossen. Keine echten Zugangsdaten committen. Die Scan-Skripte benötigen außerdem Schreibrechte auf die konfigurierten Logdateien.

## Ausführen

```bash
sudo .venv/bin/python scan.py
sudo .venv/bin/python yara_scan.py
sudo .venv/bin/python yara_without_mail.py
```

Für einen ungefährlichen Funktionstest zunächst `SCAN_ROOT` in `.env` auf ein kleines Testverzeichnis setzen. YARA-Treffer sind Prüfergebnisse und müssen manuell bewertet werden.

## Zeitgesteuerter Lauf

Cron-Beispiel für einen wöchentlichen Lauf sonntags um 02:30 Uhr (Pfad anpassen):

```cron
30 2 * * 0 root cd /opt/system-security-scans && /opt/system-security-scans/.venv/bin/python /opt/system-security-scans/scan.py >> /var/log/system-security-scans-cron.log 2>&1
```

Die Cron-Umgebung lädt `.env` relativ zum aktuellen Arbeitsverzeichnis; daher enthält der Eintrag ausdrücklich `cd`. Vor Aktivierung Laufzeit, I/O-Last und Logrotation einplanen.

## Hinweise zu den Scannern

- AIDE ist installiert und die Konfiguration (`AIDE_CONFIG`) wird bereitgestellt, der AIDE-Teil ist in `scan.py` jedoch standardmäßig deaktiviert. Eine Initialisierung der AIDE-Datenbank muss bewusst und gemäß eigener Baseline-Prozedur erfolgen.
- rkhunter benötigt nach der Installation ggf. eine passende lokale Konfiguration. Ein Exit-Code ungleich null bedeutet nicht automatisch einen Fund; stets die jeweiligen Logs bzw. Konsolenausgaben prüfen.
- ClamAV- und chkrootkit-Ergebnisse sollten ebenfalls manuell geprüft werden. Die Scanner ersetzen weder Updates noch Backups oder Incident-Response.
- Das automatisierte Skript führt keine Quarantäne oder Löschung durch.
