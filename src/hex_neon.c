#include <stdio.h>
#include <stdint.h>
#include <arm_neon.h>

const uint8_t nine = 9;
const uint8_t and_mask = 0xf;
const uint8_t bin_a = 0x37;

void sha1_to_hex_neon(const uint8_t *binary, uint8_t *hex) {
  uint8x16_t ascii_zero = vld1q_dup_u8((const uint8_t*)"0");
  uint8x16_t nines = vld1q_dup_u8(&nine);
  uint8x16_t ascii_a = vld1q_dup_u8(&bin_a);
  uint8x16_t and4bits = vld1q_dup_u8(&and_mask);

  uint8x16_t invec = vld1q_u8(binary);
  uint8x16_t masked1 = vandq_u8(invec, and4bits);
  uint8x16_t masked2 = vandq_u8(vshrq_n_u8((invec), 4), and4bits);

  uint8x16_t cmpmask1 = vcgtq_u8(masked1, nines);
  uint8x16_t cmpmask2 = vcgtq_u8(masked2, nines);

  uint8x16_t masked1_k = vaddq_u8(masked1, vbslq_u8(cmpmask1, ascii_a, ascii_zero));
  uint8x16_t masked2_k = vaddq_u8(masked2, vbslq_u8(cmpmask2, ascii_a, ascii_zero));

  uint8x16_t res1 = vzip1q_u8(masked2_k, masked1_k);
  uint8x16_t res2 = vzip2q_u8(masked2_k, masked1_k);

  vst1q_u8(hex, res1);
  vst1q_u8(hex + 16, res2);
}
