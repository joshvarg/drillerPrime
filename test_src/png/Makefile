CC=afl-gcc
all: test

test: lodepng upng
	$(CC) -o test test.c lodepng_decoder_test.o upng_decoder_test.o liblodepng.so libupng.so

lodepng: lodepng.c lodepng.h
	$(CC) -fPIC -shared -o liblodepng.so lodepng.c
	$(CC) -c -o lodepng_decoder_test.o  lodepng_decoder_test.c liblodepng.so

upng: upng.c upng.h
	$(CC) -fPIC -shared -o libupng.so upng.c
	$(CC) -c -o upng_decoder_test.o  upng_decoder_test.c libupng.so

clean:
	rm *.so *.o test