version := 0.1

all: stamps html


stamps:
	echo $(version) >verstamp
	echo `date +%D` >datestamp

html: 
	db2html -d `pwd`/stylesheet.dsl main.sgml
	mv main html

dist: all
	tar cf - html | bzip2 -9 > arch2-$(version).tar.bz2

clean:
	-test -d html && rm -rf html
	-test -d main && rm -rf main
	-test -f datestamp && rm -rf datestamp
	-test -f verstamp  && rm -rf verstamp


	
