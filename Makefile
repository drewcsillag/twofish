all: twofish-benchmark

tables.h: makeCtables.py myref.py
	python makeCtables.py > tables.h

twofish-benchmark: opt2.c tables.h
	gcc -O3 -fomit-frame-pointer -Wall -o twofish-benchmark opt2.c

clean:
	rm tables.h twofish-benchmark
