#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "aes.h"
#include "entropy.h"

int main()
{
  uint8_t key_enc[32];
  uint8_t encd_buf[17];

  getrandom(key_enc, 32, GRND_NONBLOCK);

  aesctr_t stream;
  aesctr_init(stream, key_enc, 0xfffffffffffffUL);
  aesctr_prg(stream, encd_buf, 17);
  assert(encd_buf[0] != 0);
  aesctr_clear(stream);
}
