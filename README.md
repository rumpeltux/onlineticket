# Parser für Onlinetickets der Deutschen Bahn

Hintergrund: https://itooktheredpill.irgendwo.org/2010/onlinetickets-der-bahn/

## Benutzung

Das Skript muss nicht gesondert installiert werden.
Es wird das Paket `python-pyasn1` benötigt.

Das Skript verarbeitet die im Barcode kodierten Daten, diese müssen also
zunächst aus dem Ticket extrahiert werden. Wenn man das PDF des Tickets hat
geht dies sehr leicht mit:

    sh parsepdfs.sh

Nun sollte man für jedes PDF eine `.txt` Datei mit den Daten des Barcodes
erhalten haben, die man nun an das Skript füttern kann:

    python onlineticket.py *.txt

## Bugs

Sollte das Skript mit einem Ticket nicht klarkommen, bitte einen Bug öffnen
und mir die Barcode-Daten (`.txt` Datei) zukommen lassen.
