#include <stdio.h>
#include <stdint.h>
#include <lsxintrin.h>

const uint8_t nine = 9;
const uint8_t and_mask = 0xf;
const uint8_t bin_a = 0x37;

void sha1_to_hex_lsx(const uint8_t *binary, uint8_t *hex) {
  __m128i ascii_zero = __lsx_vldrepl_b((const uint8_t*)"0", 0);
  __m128i nines = __lsx_vldrepl_b(&nine, 0);
  __m128i ascii_a = __lsx_vldrepl_b(&bin_a, 0);
  __m128i and4bits = __lsx_vldrepl_b(&and_mask, 0);

  __m128i invec = __lsx_vld((__m128i * const)binary, 0);

  __m128i masked1 = __lsx_vand_v(invec, and4bits);
  __m128i masked2 = __lsx_vand_v(__lsx_vsrli_b((invec), 4), and4bits);

  __m128i cmpmask1 = __lsx_vslt_bu(nines, masked1);
  __m128i cmpmask2 = __lsx_vslt_bu(nines, masked2);

  __m128i masked1_k = __lsx_vsadd_bu(masked1, __lsx_vbitsel_v(ascii_zero, ascii_a, cmpmask1));
  __m128i masked2_k = __lsx_vsadd_bu(masked2, __lsx_vbitsel_v(ascii_zero, ascii_a, cmpmask2));

  __m128i res1 = __lsx_vilvl_b(masked1_k, masked2_k);
  __m128i res2 = __lsx_vilvh_b(masked1_k, masked2_k);
  
  __lsx_vst(res1, hex, 0);
  __lsx_vst(res2, hex + 16, 0);
}
