//! Hex calculation with SIMD
//!
//! Based on code from [`faster-hex`](https://github.com/nervosnetwork/faster-hex)
//! Originally licensed under the terms of the MIT License.

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

#[cfg(target_arch = "aarch64")]
extern "C" {
    #[link_name = "sha1_to_hex_neon"]
    fn sha1_to_hex_neon_(binary: *const u8, hex: *mut u8);
}

#[cfg(target_arch = "loongarch64")]
#[cfg(compilerSupportLSX)]
extern "C" {
    #[link_name = "sha1_to_hex_lsx"]
    fn sha1_to_hex_lsx_(binary: *const u8, hex: *mut u8);
}

static TABLE: &[u8; 16] = b"0123456789ABCDEF";

/// SHA-1 binary to hex conversion with SSE4.1
/// We have a fixed input and output length
#[target_feature(enable = "sse4.1")]
#[cfg(target_arch = "x86_64")]
unsafe fn sha1_to_hex_sse41(binary: &[u8], hex: &mut [u8]) {
    let ascii_zero = _mm_set1_epi8(b'0' as i8);
    let nines = _mm_set1_epi8(9);
    let ascii_a = _mm_set1_epi8((b'A' - 9 - 1) as i8);
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

/// SHA-1 binary to hex conversion with SSE4.1
/// We have a fixed input and output length, and have to pad the input and output
#[target_feature(enable = "avx2")]
#[cfg(target_arch = "x86_64")]
unsafe fn sha1_to_hex_avx2(binary: &[u8], hex: &mut [u8]) {
    // Preparing padded input and output
    let mut padded_output: [u8; 64] = [0x0; 64];
    let mut padded_input: [u8; 32] = [0x0; 32];
    std::ptr::copy_nonoverlapping(binary.as_ptr(), padded_input.as_mut_ptr(), 20);

    let ascii_zero = _mm256_set1_epi8(b'0' as i8);
    let nines = _mm256_set1_epi8(9);
    let ascii_a = _mm256_set1_epi8((b'A' - 9 - 1) as i8);
    let and4bits = _mm256_set1_epi8(0xf);

    let invec = _mm256_loadu_si256(padded_input.as_ptr() as *const _);
    let masked1 = _mm256_and_si256(invec, and4bits);
    let masked2 = _mm256_and_si256(_mm256_srli_epi64(invec, 4), and4bits);
    // return 0xff corresponding to the elements > 9, or 0x00 otherwise
    let cmpmask1 = _mm256_cmpgt_epi8(masked1, nines);
    let cmpmask2 = _mm256_cmpgt_epi8(masked2, nines);

    // add '0' or the offset depending on the masks
    let masked1 = _mm256_add_epi8(masked1, _mm256_blendv_epi8(ascii_zero, ascii_a, cmpmask1));
    let masked2 = _mm256_add_epi8(masked2, _mm256_blendv_epi8(ascii_zero, ascii_a, cmpmask2));

    // interleave masked1 and masked2 bytes
    let res1 = _mm256_unpacklo_epi8(masked2, masked1);
    let res2 = _mm256_unpackhi_epi8(masked2, masked1);

    // Store everything into the right destination now
    let base = padded_output.as_mut_ptr();
    let base1 = base.offset(0) as *mut _;
    let base2 = base.offset(16) as *mut _;
    let base3 = base.offset(32) as *mut _;
    let base4 = base.offset(48) as *mut _;
    _mm256_storeu2_m128i(base3, base1, res1);
    _mm256_storeu2_m128i(base4, base2, res2);

    std::ptr::copy_nonoverlapping(padded_output.as_ptr(), hex.as_mut_ptr(), 40);
}

#[cfg(target_arch = "aarch64")]
unsafe fn sha1_to_hex_neon(binary: &[u8], hex: &mut [u8]) {
    sha1_to_hex_neon_(binary.as_ptr(), hex.as_mut_ptr());

    hex_fallback(&binary[16..], &mut hex[32..]);
}

#[cfg(target_arch = "loongarch64")]
#[cfg(compilerSupportLSX)]
unsafe fn sha1_to_hex_lsx(binary: &[u8], hex: &mut [u8]) {
    sha1_to_hex_lsx_(binary.as_ptr(), hex.as_mut_ptr());

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

    if cfg!(target_arch = "x86_64") {
        #[cfg(target_arch = "x86_64")]
        if is_x86_feature_detected!("avx2") {
            unsafe { sha1_to_hex_avx2(binary, &mut result) }
        } else if is_x86_feature_detected!("sse4.1") {
            unsafe { sha1_to_hex_sse41(binary, &mut result) }
        } else {
            hex_fallback(binary, &mut result);
        }
    } else if cfg!(target_arch = "aarch64") {
        #[cfg(target_arch = "aarch64")]
        unsafe {
            sha1_to_hex_neon(binary, &mut result)
        }
    } else if cfg!(target_arch = "loongarch64") {
        if cfg!(compilerSupportLSX) {
            unsafe { sha1_to_hex_lsx(binary, &mut result) }
        } else {
            hex_fallback(binary, &mut result);
        }
    } else {
        hex_fallback(binary, &mut result);
    }

    unsafe { String::from_utf8_unchecked(result) }
}

#[cfg(test)]
mod hex_test {
    use super::sha1_to_hex;
    #[cfg(target_arch = "x86_64")]
    use super::{sha1_to_hex_avx2, sha1_to_hex_sse41};
    use hex::encode_upper;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_sha1_to_hex_sse41() {
        if is_x86_feature_detected!("sse4.1") {
            let data: &[u8; 20] = b"0123456789ABCDEFGHIJ";
            let mut result: Vec<u8> = vec![0x0; 40];
            unsafe {
                sha1_to_hex_sse41(data, &mut result);
            }
            let hex_string = unsafe { String::from_utf8_unchecked(result) };
            assert_eq!(hex_string, encode_upper(data));
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_sha1_to_hex_avx2() {
        if is_x86_feature_detected!("avx2") {
            let data: &[u8; 20] = b"0123456789ABCDEFGHIJ";
            let mut result: Vec<u8> = vec![0x0; 40];
            unsafe {
                sha1_to_hex_avx2(data, &mut result);
            }
            let hex_string = unsafe { String::from_utf8_unchecked(result) };
            assert_eq!(hex_string, encode_upper(data));
        }
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_sha1_to_hex_neon() {
        use super::sha1_to_hex_neon;
        let data: &[u8; 20] = b"0123456789ABCDEFGHIJ";
        let mut result: Vec<u8> = vec![0x0; 40];
        unsafe {
            sha1_to_hex_neon(data, &mut result);
        }
        let hex_string = unsafe { String::from_utf8_unchecked(result) };
        assert_eq!(hex_string, encode_upper(data));
    }

    #[test]
    #[cfg(target_arch = "loongarch64")]
    #[cfg(compilerSupportLSX)]
    fn test_sha1_to_hex_lsx() {
        use super::sha1_to_hex_lsx;
        let data: &[u8; 20] = b"0123456789ABCDEFGHIJ";
        let mut result: Vec<u8> = vec![0x0; 40];
        unsafe {
            sha1_to_hex_lsx(data, &mut result);
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
