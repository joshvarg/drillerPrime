all: test

test: test.c test.h tiny-regex-c/re.c tiny-regex-c/re.h
	afl-gcc --static -o test test.c tiny-regex-c/re.c
	gcc --static -o test_noinst test.c tiny-regex-c/re.c

clean:
	rm *.o test_noinst test
