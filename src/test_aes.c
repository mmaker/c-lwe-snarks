#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "aes.h"
#include "entropy.h"

int main()
{
  uint8_t key[32];
  uint8_t buf[16];

  getrandom(key, 32, GRND_NONBLOCK);

  aesctr_t stream;
  aesctr_init(stream, key, 0xfffffffffffffUL);
  aesctr_prg(stream, buf, 16);
  assert(buf[0] != 0);

  uint8_t buf2[16];
  aesctr_prg(stream, buf2, 16);
  assert(buf[0] != buf2[0]);

  aesctr_clear(stream);
}
