//! Hex calculation with SIMD
//!
//! Based on code from [`faster-hex`](https://github.com/nervosnetwork/faster-hex)
//! and [a GitHub Gist](https://gist.github.com/0x1F9F1/cba054c667c4e8525d9b12c99fdab7fb)
//! Originally licensed under the terms of the MIT License.

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

static TABLE: &[u8; 16] = b"0123456789ABCDEF";

/// SHA-1 binary to hex conversion with SSE4.1
/// We have a fixed input and output length
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_feature = "sse4.1"))]
unsafe fn sha1_to_hex_sse41(binary: &[u8], hex: &mut [u8]) {
    let ascii_zero = _mm_set1_epi8(b'0' as i8);
    let nines = _mm_set1_epi8(9);
    let ascii_a = _mm_set1_epi8((b'a' - 9 - 1) as i8);
    let and4bits = _mm_set1_epi8(0xf);

    let invec = _mm_loadu_si128(binary.as_ptr() as *const _);

    let masked1 = _mm_and_si128(invec, and4bits);
    let masked2 = _mm_and_si128(_mm_srli_epi64(invec, 4), and4bits);

    // return 0xff corresponding to the elements > 9, or 0x00 otherwise
    let cmpmask1 = _mm_cmpgt_epi8(masked1, nines);
    let cmpmask2 = _mm_cmpgt_epi8(masked2, nines);

    // add '0' or the offset depending on the masks
    let masked1 = _mm_add_epi8(masked1, _mm_blendv_epi8(ascii_zero, ascii_a, cmpmask1));
    let masked2 = _mm_add_epi8(masked2, _mm_blendv_epi8(ascii_zero, ascii_a, cmpmask2));

    // interleave masked1 and masked2 bytes
    let res1 = _mm_unpacklo_epi8(masked2, masked1);
    let res2 = _mm_unpackhi_epi8(masked2, masked1);

    _mm_storeu_si128(hex.as_mut_ptr() as *mut _, res1);
    _mm_storeu_si128(hex.as_mut_ptr().offset(16) as *mut _, res2);

    hex_fallback(&binary[16..], &mut hex[32..]);
}

/// Software implementation of binary to hex
fn hex_fallback(binary: &[u8], hex: &mut [u8]) {
    for (byte, slots) in binary.iter().zip(hex.chunks_mut(2)) {
        slots[0] = TABLE[((*byte >> 4) & 0xF) as usize];
        slots[1] = TABLE[(*byte & 0xF) as usize];
    }
}

/// SHA-1 binary to hex
pub fn sha1_to_hex(binary: &[u8]) -> String {
    let mut result: Vec<u8> = vec![0x0; 40];

    if cfg!(all(target_arch = "x86_64", target_feature = "sse4.1")) {
        #[cfg(all(target_arch = "x86_64", target_feature = "sse4.1"))]
        unsafe {
            sha1_to_hex_sse41(binary, &mut result);
        }
    } else {
        hex_fallback(binary, &mut result);
    }

    unsafe { String::from_utf8_unchecked(result) }
}

#[cfg(test)]
mod hex_test {
    use super::{sha1_to_hex, sha1_to_hex_sse41};
    use hex::encode_upper;

    #[test]
    fn test_sha1_to_hex_sse41() {
        let data: &[u8; 20] = b"0123456789ABCDEFGHIJ";
        let mut result: Vec<u8> = vec![0x0; 40];
        unsafe {
            sha1_to_hex_sse41(data, &mut result);
        }
        let hex_string = unsafe { String::from_utf8_unchecked(result) };
        assert_eq!(hex_string, encode_upper(data));
    }

    #[test]
    fn test_sha1_to_hex() {
        let data: &[u8; 20] = b"0123456789ABCDEFGHIJ";
        assert_eq!(sha1_to_hex(data), encode_upper(data));
    }
}
