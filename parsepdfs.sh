#!/bin/sh
# Usage: ./parsepdf.sh *.pdf

SCRIPTDIR=$(dirname $0)

# Download the binaries (if not yet existing)
VERSION=3.3.1
for lib in core javase; do
  [ -e $SCRIPTDIR/zx-$lib.jar ] || wget https://repo1.maven.org/maven2/com/google/zxing/$lib/$VERSION/$lib-$VERSION.jar -O $SCRIPTDIR/zx-$lib.jar
done
[ -e $SCRIPTDIR/jcommander.jar ] || wget https://repo1.maven.org/maven2/com/beust/jcommander/1.72/jcommander-1.72.jar -O $SCRIPTDIR/jcommander.jar

for file in $@; do
  echo "$file: image extraction"
  pdfimages "$file" "$file"
  echo "$file: image conversion"
  for i in "$file"*.pbm "$file"*.ppm; do
    convert "$i" "$i.png"
    rm "$i"
  done
  echo "$file: barcode extraction"
  for i in "$file"*.png; do
    if file "$i" | grep -q 1-bit; then
      java -cp $SCRIPTDIR/zx-core.jar:$SCRIPTDIR/zx-javase.jar:$SCRIPTDIR/jcommander.jar \
          com.google.zxing.client.j2se.CommandLineRunner \
          --pure_barcode --dump_results --brief ./$i
    fi
    rm "$i"
  done
done
