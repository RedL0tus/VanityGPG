#include <stdio.h>
#include <stdint.h>
#include <msa.h>

const uint8_t nine = 9;
const uint8_t and_mask = 0xf;
const uint8_t bin_a = 0x37;
const uint8_t zero = '0';

void sha1_to_hex_msa(const uint8_t *binary, uint8_t *hex) {
  v16u8 ascii_zero = __msa_fill_b(zero);
  v16u8 nines = __msa_fill_b(nine);
  v16u8 ascii_a = __msa_fill_b(bin_a);
  v16u8 and4bits = __msa_fill_b(and_mask);

  v16u8 bin_vec = __msa_ld_b((void *)binary, 0);
  v16u8 masked1 = __msa_and_v(bin_vec, and4bits);
  v16u8 masked2 = __msa_and_v(__msa_srli_b((bin_vec), 4), and4bits);

  // compare masked1 greater than nines
  v16u8 cmpmask1 = __msa_clt_u_b(nines, masked1);
  v16u8 cmpmask2 = __msa_clt_u_b(nines, masked2);

  // add based on bit select
  v16u8 masked1_k =
      __msa_addv_b(masked1, __msa_bsel_v(cmpmask1, ascii_zero, ascii_a));
  v16u8 masked2_k =
      __msa_addv_b(masked2, __msa_bsel_v(cmpmask2, ascii_zero, ascii_a));

  // zip results back
  // note that MSA uses ilv{l,r}.b wd,ws,wt where wt has lower index
  // instead.
  // the definition of left is higher index.
  v16u8 res1 = __msa_ilvl_b(masked1_k, masked2_k);
  v16u8 res2 = __msa_ilvr_b(masked1_k, masked2_k);
  __msa_st_b(res1, hex, 16);
  __msa_st_b(res2, hex, 0);
}
