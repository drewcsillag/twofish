all: twofish-benchmark

tables.h: makeCtables.py myref.py
	python makeCtables.py > tables.h

twofish-benchmark: twofish.c tables.h
	gcc -O3 -fomit-frame-pointer -Wall -o twofish-benchmark twofish.c benchmark.c

clean:
	rm tables.h twofish-benchmark
