#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "aes.h"
#include "entropy.h"

int main()
{
  uint8_t key_enc[32];
  uint8_t encd_buf[16 * 4];

  getrandom(key_enc, 32, GRND_NONBLOCK);

  aesctr_t *stream = aesctr_init(key_enc, 0xfffffffffffffUL);
  if (stream) {
    aesctr_prg(stream, encd_buf, 0, 3);
    aesctr_clear(stream);
    return EXIT_SUCCESS;
  } else {
    return EXIT_FAILURE;
  }
}
