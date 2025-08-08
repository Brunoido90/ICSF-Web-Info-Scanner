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
1️⃣ Python installieren
Lade die aktuelle Python-Version (3.10 oder neuer) von der offiziellen Seite herunter:
🔗 https://www.python.org/downloads/

Wichtig: Beim Installieren den Haken setzen bei "Add Python to PATH".

Installation abschließen.

2️⃣ Projekt herunterladen
Variante A: GitHub-Repository klonen

bash
Kopieren
Bearbeiten
git clone https://github.com/Brunoido90/ICSF-Web-Info-Scanner
cd ICSF-Web-Info-Scanner
Variante B: ZIP-Datei von GitHub herunterladen und entpacken.

3️⃣ Benötigte Python-Module installieren
Öffne ein Terminal (CMD oder PowerShell in Windows) und führe aus:

bash
Kopieren
Bearbeiten
pip install requests colorama dnspython python-whois geoip2
💡 Falls du mehrere Python-Versionen hast:

bash
Kopieren
Bearbeiten
python -m pip install requests colorama dnspython python-whois geoip2
4️⃣ Tool starten
bash
Kopieren
Bearbeiten
python WebInfoScanner.py
Du wirst nach einer Ziel-URL gefragt:

text
Kopieren
Bearbeiten
[?] Website-URL (z.B. example.com):
Drücke Enter – der Scan startet.

5️⃣ Ergebnisse ansehen
Farbausgabe in der Konsole

Automatische Speicherung der Ergebnisse als Textdatei auf dem Desktop

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

