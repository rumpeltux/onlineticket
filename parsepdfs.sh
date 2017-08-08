ZX=$(dirname $0)
CORE=$(echo $ZX/core*.jar)
JAVASE=$(echo $ZX/javase*.jar)
VERSION=3.1.0
[ -e $JAVASE ] || wget http://repo1.maven.org/maven2/com/google/zxing/javase/$VERSION/javase-$VERSION.jar
[ -e $CORE ] || wget http://repo1.maven.org/maven2/com/google/zxing/core/$VERSION/core-$VERSION.jar
rename -v 'tr/ ()/___/' *
for i in *.pdf; do pdfimages $i $i; done
for i in *.pbm *.ppm; do convert $i $i.png; rm $i; done
for i in `file *.png | grep 1-bit | cut -f1 -d:`; do
    java -cp $CORE:$JAVASE \
        com.google.zxing.client.j2se.CommandLineRunner \
        --pure_barcode --dump_results --brief ./$i
done

