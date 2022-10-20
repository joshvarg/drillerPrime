#include <stdio.h>
#include <unistd.h>

#include "test.h"

#include "upng.h"
#include "lodepng.h"

#include "upng_decoder_test.h"
#include "lodepng_decoder_test.h"

#define EXIT_FAILURE 1

int main(int argc, char **argv) {
  int upng_test_res, lodepng_test_res;
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

  if(DEBUG)printf("\nDEBUG: back in main. lodepng decoder result: %i\n", lodepng_test_res);
  if(!DEBUG)printf("INFO: decoding has been completed. upng returned %i and lodepng returned %i.\n", upng_test_res, lodepng_test_res);
  return 0;
}

