# Parser für Onlinetickets der Deutschen Bahn

Hintergrund: https://itooktheredpill.irgendwo.org/2010/onlinetickets-der-bahn/

## Installation & Abhängigkeiten

Das Skript muss nicht gesondert installiert werden.
Es wird das Paket `python-pyasn1` benötigt.
`parsepdfs.sh` benötigt zusätzlich `poppler-utils` and `imagemagick` um die
Bilder aus den PDFs zu extrahieren, sowie eine funktionierende
Java-Installation um den Barcode mithilfe von zxing zu dekodieren.

## Benutzung

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
