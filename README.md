🕵️‍♂️ ICSF Web-Info-Scanner – Brutal Edition
Ein erweiterter Reconnaissance-Scanner im Mr. Robot-Style, entwickelt im Rahmen des Immersive Cybersecurity Simulation Framework (ICSF).
Dieses Tool sammelt umfangreiche Informationen über eine Ziel-Webseite, nur für autorisierte Sicherheitstests in einer legalen und isolierten Umgebung.

🚀 Features
🌐 IP & Reverse DNS Lookup

🔍 WHOIS-Domain-Informationen

🛡 SSL-Zertifikatsanalyse (Aussteller, Ablaufdatum, Algorithmus)

🧩 CMS & Framework Erkennung (WordPress, Joomla, React, Vue, uvm.)

🍪 Cookie-Auflistung

📡 TCP & UDP Portscan (Top 1024 Ports)

🧭 Geo-IP Standortabfrage

📜 HTTP-Security-Header Check

📂 Subdomain-Suche & Directory-Enumeration

🗂 DNS-Record-Auflistung (A, MX, TXT, NS, CNAME)

💾 Automatische Report-Erstellung auf dem Desktop

⚠️ Haftungsausschluss
Dieses Tool ist nur für:

Eigene Systeme

Systeme mit ausdrücklicher Erlaubnis des Besitzers

Geschlossene Laborumgebungen (z. B. VM, Testnetzwerke)

Jeglicher Missbrauch ist illegal und kann strafrechtlich verfolgt werden.
Der Entwickler übernimmt keine Haftung für Schäden oder unautorisierte Nutzung.

🛠 Installation
Voraussetzungen
Python 3.10 oder neuer

Windows oder Linux

Internetverbindung (für WHOIS & Geo-IP)

Benötigte Module installieren
bash
Kopieren
Bearbeiten
pip install requests colorama dnspython python-whois geoip2
📦 Nutzung
bash
Kopieren
Bearbeiten
python WebInfoScanner.py
Du wirst nach einer Ziel-URL gefragt:

text
Kopieren
Bearbeiten
[?] Website-URL (z.B. example.com):
Der Scan läuft, und das Ergebnis wird farbig in der Konsole angezeigt und in einer Textdatei auf dem Desktop gespeichert.

📑 Beispielausgabe
yaml
Kopieren
Bearbeiten
[📌 Ziel: http://example.com]
------------------------------------------------------------
🔹 IP-Adresse: 93.184.216.34
🔹 Reverse DNS: example.com
🔹 Server: nginx
🔹 Technologien: WordPress, PHP 8.0
🔹 Cookies: {'sessionid': 'xyz123'}
🔹 HTTP-Status: 200
🔹 Offene TCP-Ports: 80, 443
🔹 Offene UDP-Ports: 53
🔹 Geo-IP: USA, Los Angeles (ISP: Example ISP)
🔹 WHOIS: Registriert am 2000-01-01, Registrar: ExampleRegistrar
...
[+] Ergebnisse gespeichert auf Desktop: scan_log_YYYY-MM-DD_HH-MM-SS.txt
📜 Lizenz
Dieses Projekt steht unter der MIT-Lizenz.
Frei zur Nutzung, Modifikation und Verteilung – aber nur legal.
