# Parser für Onlinetickets der Deutschen Bahn

Hintergrund: https://itooktheredpill.irgendwo.org/2010/onlinetickets-der-bahn/

## Weitere Quellen

Im Laufe der Jahre sind weitere Quellen hinzugekommen
(siehe [#4](https://github.com/rumpeltux/onlineticket/issues/4):

* [Kontrolle des UIC 918.3*-Barcodes](https://web.archive.org/web/20180905231149/https://www.bahn.de/p/view/angebot/regio/barcode.shtml)
  mit weiteren interessanten Informationen und Links.
* [dbuic2vdvbc](https://sourceforge.net/projects/dbuic2vdvbc/), eine
  Referenzimplementierung für die Dekodierung, geschrieben in C. Beim Bauen des
  Quellcodes kann das `configure`-Skript mit dem Parameter
  `--enable-build-doc=yes` aufgerufen werden (und dann `make`), um die
  Dokumentation zusätzlich zu der `libdbuic2vdvbc.a` zu erstellen. Außerdem sind
  viele Beispiele und auch Beispieldaten enthalten.
* [B@hnDirekt – Interoperabilität Barcode DB Online-Ticket VDV- KA](https://web.archive.org/web/20180905231217/https://www.bahn.de/p/view/mdb/bahnintern/angebotsberatung/regio/barcode/mdb_220334_interoperabilitaet_barcode_db_online-ticketvdv-ka_v1_4.pdf)
  mit weiteren Informationen.
* Die [VDV-Kernapplikation](https://oepnv.eticket-deutschland.de/produkte-und-services/vdv-kernapplikation/#slide2),
deren relevante Downloads offenbar allerdings nur nach einer Registierung oder
  Bezahlung eines Endbetrages verfügbar sind.
* https://railpublickey.uic.org/: Internationale Liste von im Eisenbahnverkehr verwendeten Signaturen
* [Javascript Implementierung](https://github.com/justusjonas74/uic-918-3)

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

    ./parsepdfs.sh *.pdf

Nun sollte man für jedes PDF eine `.txt` Datei mit den Daten des Barcodes
erhalten haben, die man nun an das Skript füttern kann:

    python3 onlineticket.py *.txt

## Bugs

Sollte das Skript mit einem Ticket nicht klarkommen, bitte einen Bug öffnen
und mir die Barcode-Daten (`.txt` Datei) zukommen lassen.
