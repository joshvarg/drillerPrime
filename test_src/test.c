#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

#include "test.h"

#include "upng.h"
#include "lodepng.h"

#include "upng_decoder_test.h"
#include "lodepng_decoder_test.h"

#define EXIT_FAILURE 1

int main(int argc, char **argv) {
  int upng_test_res, lodepng_test_res;
  int log_count = 0;
  char* log_file = "log.txt";
  char* latest_poc = "poc";
  int chr;
  FILE* poc;
  FILE* input;
  FILE* log;
  if(DEBUG)puts("DEBUG: running main");
  if(argc < 2){
        fprintf(stderr, "Usage: %s <png>\n", argv[0]);
        return EXIT_FAILURE;
  }
  
  if(DEBUG)printf("DEBUG: executing upng decoder\n\n");
  upng_test_res = upng_decoder_test(argv[1]);
 
  /* we get the result from the upng decoder. 0 == success; otherwise, failure. */
  if(DEBUG)printf("\nDEBUG: back in main. upng decoder result: %i\n\n", upng_test_res); 
  
  if(DEBUG)puts("DEBUG: executing lodepng decoder");
  lodepng_test_res = lodepng_decoder_test(argv[1]);
  
  log = fopen(log_file, "a");
  /* Differential fuzzing*/
  if((upng_test_res == UPNG_EOK) != (lodepng_test_res == 0) && strcmp(argv[1], latest_poc)){
    if(DEBUG)puts("DEBUG: program outputs differ");
    
    poc = fopen(latest_poc, "w");
    input = fopen(argv[1], "r");
    if(poc && input){
      while((chr = fgetc(input)) != EOF){
        fputc(chr, poc);
      }
      fclose(poc);
      fclose(input);
    }
    if(log){
      fprintf(log, "u:%d lode:%d\n", upng_test_res, lodepng_test_res);
    }
  } else {
    if(DEBUG)puts("DEBUG: program outputs match");
  }
  if(log){
    fclose(log);
  }
  if(DEBUG)printf("\nDEBUG: back in main. lodepng decoder result: %i\n", lodepng_test_res);
  if(!DEBUG)printf("INFO: decoding has been completed. upng returned %i and lodepng returned %i.\n", upng_test_res, lodepng_test_res);
  assert(upng_test_res == 0 && lodepng_test_res == 0 || upng_test_res != 0 && lodepng_test_res != 0);
  return 0;
}

