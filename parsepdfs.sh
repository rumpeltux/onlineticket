ZX=/home/rumpel/Private/projects/zxing
rename -v 'tr/ ()/___/' *
for i in *.pdf; do pdfimages $i $i; done
for i in *.pbm *.ppm; do convert $i $i.png; rm $i; done
for i in `file *.png | grep 1-bit | cut -f1 -d:`; do
    java -cp $ZX/core/core.jar:$ZX/javase/javase.jar \
        com.google.zxing.client.j2se.CommandLineRunner \
        --pure_barcode --dump_results --brief $i
done

