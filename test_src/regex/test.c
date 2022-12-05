#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include "test.h"
#include "tiny-regex-c/re.h"

#include <sys/types.h>
#include <regex.h>
#include <string.h>

#define EXIT_FAILURE 1
#define MAX_INPUT_LEN 30
void diff_fuzz(char* input, int* tiny_res, int* libc_res){
  char* log_file = "log.txt";
  re_t tiny_regex;
  regex_t preg;
  FILE* log;
  if(DEBUG)printf("DEBUG: executing upng decoder\n\n");
  tiny_regex = re_compile(input);
  /* 1 on success (tiny_regex is nonzero)*/
  *tiny_res = (tiny_regex != 0);
 
  if(DEBUG)printf("\nDEBUG: tiny compile result: %i\n\n", *tiny_res); 
  
  if(DEBUG)puts("DEBUG: executing lodepng decoder");
  /* 1 on success (regcomp returns zero)*/
  *libc_res = (regcomp(&preg, input, 0) == 0);
  if(DEBUG)printf("\nDEBUG: libc compile result: %i\n\n", *libc_res); 
  log = fopen(log_file, "a");
  /* Differential fuzzing*/
  if(*tiny_res != *libc_res){
    if(DEBUG)puts("DEBUG: program outputs differ");
    if(log){
      fprintf(log, "tiny:%d libc:%d pattern:%s\n", *tiny_res, *libc_res, input);
    }
  } else {
    if(DEBUG)puts("DEBUG: program outputs match");
  }
  if(log){
    fclose(log);
  }
  
}

int main(int argc, char **argv) {
  int libc_res;
  int tiny_res;

  char buf[MAX_INPUT_LEN+1];


  if(fgets(buf, MAX_INPUT_LEN, stdin) == NULL){
    if(DEBUG)printf("DEBUG: Error reading from fgets\n");
    return 0;
  }
  buf[strlen(buf)] = '\0';
  /* Initialize AFL after the input file has been parsed. Need to compile with afl-clang-fast.*/
  #ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
  #endif
  /* Inititate differential fuzzing. DrillerPime will start execution from here and skip initialization code. */
  diff_fuzz(buf, &tiny_res, &libc_res);
  
  if(!DEBUG)printf("INFO: decoding has been completed. tiny result %i and lodepng result %i.\n", libc_res, tiny_res);
  assert(libc_res == 0 && tiny_res == 0 || libc_res != 0 && tiny_res != 0);
  return 0;
}
