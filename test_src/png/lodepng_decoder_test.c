#include <stdio.h>
#include <stdlib.h>
#include "test.h"
#include "lodepng.h"
#include "lodepng_decoder_test.h"

int lodepng_decoder_test(char *png_ptr) {
  unsigned decoder_res;
  unsigned char* image = 0;
  unsigned char* png = 0;
  unsigned width, height;
  size_t pngsize;
  LodePNGState state;
  
  if(DEBUG)puts("DEBUG: inside lodepng_decoder_test");
  if(DEBUG)puts("DEBUG: decoding png input");

  lodepng_state_init(&state);
  state.decoder.ignore_crc = 1;

  /* invoke decoder and look for errors. 0 == success; otherwise, failure.*/
  decoder_res = lodepng_load_file(&png, &pngsize, png_ptr);
  if(!decoder_res){
      decoder_res = lodepng_decode(&image, &width, &height, &state, png, pngsize);
  }
  
  if(decoder_res) {
        printf("error %u: %s\n", decoder_res, lodepng_error_text(decoder_res));
  }else{
        if(DEBUG)puts("DEBUG: lodepng decoder was successful");
  }
  /* decoding is complete and we free resources */
  free(image);
  
  return decoder_res;
}

