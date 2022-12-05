#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include "test.h"

#include "upng.h"
#include "lodepng.h"

#include "upng_decoder_test.h"
#include "lodepng_decoder_test.h"

#define EXIT_FAILURE 1
void diff_fuzz(char* png, int* lodepng_test_res, int* upng_test_res){
  char* log_file = "log.txt";
  FILE* log;
  if(DEBUG)printf("DEBUG: executing upng decoder\n\n");
  *upng_test_res = upng_decoder_test(png);
 
  /* we get the result from the upng decoder. 0 == success; otherwise, failure. */
  if(DEBUG)printf("\nDEBUG: back in main. upng decoder result: %i\n\n", *upng_test_res); 
  
  if(DEBUG)puts("DEBUG: executing lodepng decoder");
  *lodepng_test_res = lodepng_decoder_test(png);
  
  log = fopen(log_file, "a");
  /* Differential fuzzing*/
  if((*upng_test_res == UPNG_EOK) != (*lodepng_test_res == 0)){
    if(DEBUG)puts("DEBUG: program outputs differ");
    if(log){
      fprintf(log, "u:%d lode:%d\n", *upng_test_res, *lodepng_test_res);
    }
  } else {
    if(DEBUG)puts("DEBUG: program outputs match");
  }
  if(log){
    fclose(log);
  }
  
}
int main(int argc, char **argv) {
  int upng_test_res, lodepng_test_res;
  
  char temp_path[] = "/tmp/fuzz_XXXXXX";
  FILE* temp_file;
  int temp_fd;
  char buf;
  if(DEBUG)puts("DEBUG: running main");
  if(DEBUG)puts("DEBUG: reading stdin to temp file");
  temp_fd = mkstemp(temp_path);
  if(temp_fd < 0){
    if(DEBUG)puts("DEBUG: error creating temp file");
    return 0;
  }
  close(temp_fd);
  temp_file = fopen(temp_path, "w+b");
  if(!temp_file){
    if(DEBUG)puts("DEBUG: error opening temp file");
    unlink(temp_path);
    
    return 0;
  }

  while(fread(&buf, 1, 1, stdin) > 0){
      fwrite(&buf, 1, 1, temp_file);
  }
  fclose(temp_file);
  if(DEBUG)printf("DEBUG: copied input to temp file %s\n", temp_path);
  
  /* Initialize AFL after the input file has been parsed. Need to compile with afl-clang-fast.*/
  #ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
  #endif
  /* Inititate differential fuzzing. DrillerPime will start execution from here and skip initialization code. */
  diff_fuzz(temp_path, &lodepng_test_res, &upng_test_res);
  
  if(unlink(temp_path) < 0){
    if(DEBUG)printf("DEBUG: error deleting temp file %s\n", temp_path);
  }	
  if(DEBUG)printf("\nDEBUG: back in main. lodepng decoder result: %i\n", lodepng_test_res);
  if(!DEBUG)printf("INFO: decoding has been completed. upng returned %i and lodepng returned %i.\n", upng_test_res, lodepng_test_res);
  assert(upng_test_res == 0 && lodepng_test_res == 0 || upng_test_res != 0 && lodepng_test_res != 0);
  return 0;
}
