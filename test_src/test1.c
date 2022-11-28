#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include "test.h"

#include "upng.h"
#include "lodepng/lodepng.h"

#include "upng_decoder_test.h"
#include "lodepng_decoder_test.h"

#define EXIT_FAILURE 1
#define NCHAR 128

void diff_fuzz(char* png, int* lodepng_test_res, int* upng_test_res){
  //char* log_file = "log.txt";
  //FILE* log;
  //if(DEBUG)printf("DEBUG: executing upng decoder\n\n");
  *upng_test_res = upng_decoder_test(png);
 
  /* we get the result from the upng decoder. 0 == success; otherwise, failure. */
  //if(DEBUG)printf("\nDEBUG: back in main. upng decoder result: %i\n\n", *upng_test_res); 
  
  //if(DEBUG)puts("DEBUG: executing lodepng decoder");
  *lodepng_test_res = lodepng_decoder_test(png);
  
  //log = fopen(log_file, "a");
  /* Differential fuzzing*/
  if((*upng_test_res == UPNG_EOK) != (*lodepng_test_res == 0)){
    //if(DEBUG)puts("DEBUG: program outputs differ");
    //if(log){
    //  fprintf(log, "u:%d lode:%d\n", *upng_test_res, *lodepng_test_res);
    //}
  } else {
    //if(DEBUG)puts("DEBUG: program outputs match");
  }
  //if(log){
  //  fclose(log);
  //}
  
}
int main(int argc, char **argv) {
  int upng_test_res = 0, lodepng_test_res = 0;
  //FILE* fp;
  int c;
  
  //char temp_path[] = "/tmp/fuzz_XXXXXX";
  //FILE* temp_file = ;
  //int temp_fd = 0;
  //char buffer[2399];
  //if(DEBUG)puts("DEBUG: running main");
  //if(DEBUG)puts("DEBUG: reading stdin to temp file");
  //temp_fd = mkstemp(temp_path);
  //if(temp_fd < 0){
  //  if(DEBUG)puts("DEBUG: error creating temp file");
  //  return 0;
  //}
  //close(temp_fd);
  //temp_file = fopen(temp_path, "w+b");
  //if(!temp_file){
  //  if(DEBUG)puts("DEBUG: error opening temp file");
  //  unlink(temp_path);
    
  //  return 0;
  //}
    size_t n = 0, nchar = NCHAR;
    char* png = "s.png";
    char *arr = malloc (sizeof *arr * nchar);
    FILE *fp = stdin;
    /*
    if (!fp) {   validate file open for reading 
        fprintf (stderr, "error: file open failed '%s'.\n", argv[1]);
        return 1;
    }
    */
    if (!arr) { /* validate memory allocation succeeded */
        fprintf (stderr, "error: virtual memory exhausted.\n");
        return 1;
    }
  //read(0 , buffer, 2399);
  //if (fp == stdin){
      while ((c = fgetc (fp)) != EOF) {  /* for each char in file */
        arr[n++] = c;       /* assign char to array */

        if (n == nchar) {   /* realloc preserving space for nul */
            void *tmp = realloc (arr, nchar + NCHAR);
            if (!tmp) {           /* validate realloc succeeded */
                fprintf (stderr, "realloc() error: memory exhausted.\n");
                break; /* break read loop, using existing 'arr' */
            }
            arr = tmp;     /* assign reallocated pointer to arr */
            nchar += NCHAR;        /* update the value of nchar */
        }
    }
    
  FILE* fp1 = fopen("s.png", "wb");
  fwrite(arr, sizeof(char), n, fp1);
  fclose(fp1);
  png = "s.png";
  //}
  //fclose(temp_file);
  //if(DEBUG)printf("DEBUG: copied input to temp file %s\n", temp_path);
  
  /* Initialize AFL after the input file has been parsed. Need to compile with afl-clang-fast.*/
  //#ifdef __AFL_HAVE_MANUAL_CONTROL
  //  __AFL_INIT();
  //#endif
  /* Inititate differential fuzzing. DrillerPime is to start execution from here and skip initialization code. */
  //diff_fuzz("s.png", &lodepng_test_res, &upng_test_res);
  upng_test_res = upng_decoder_test(png);
  lodepng_test_res = lodepng_decoder_test(png);
  //if(unlink(temp_path) < 0){
  //  if(DEBUG)printf("DEBUG: error deleting temp file %s\n", temp_path);
  //}
  //if(DEBUG)printf("\nDEBUG: back in main. lodepng decoder result: %i\n", lodepng_test_res);
  //if (fp != stdin) fclose (fp); 
  free (arr);
  if(!DEBUG)printf("INFO: decoding has been completed. upng returned %i and lodepng returned %i.\n", upng_test_res, lodepng_test_res);
  assert(upng_test_res == 0 && lodepng_test_res == 0 || upng_test_res != 0 && lodepng_test_res != 0);
  return 0;
}
