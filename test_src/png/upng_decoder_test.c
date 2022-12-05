#include <stdio.h>
#include <unistd.h>

#include "test.h"

#include "upng.h"
#include "upng_decoder_test.h" 

int upng_decoder_test(char *png_ptr) {
  upng_t* upng;
  int upng_decoder_res = 0;
  
  if(DEBUG)puts("DEBUG: inside upng_decoder_test");  
  
  upng = upng_new_from_file(png_ptr);
  if (upng != NULL) {
    if(DEBUG)puts("DEBUG: upng has been created. Executing decoder.");
    /* decode png */
    upng_decode(upng);
    
    /* determine success status */
    upng_decoder_res = upng_get_error(upng);
    /* check for success, which is determined when result == 0 */
    if(upng_decoder_res == UPNG_EOK){ 
            if(DEBUG)puts("DEBUG: decoder was successful");
    }else{
            if(DEBUG)puts("DEBUG: decoder was unsuccessful");
    }

    /* free resources */
    upng_free(upng);
  }
  return upng_decoder_res;
}

