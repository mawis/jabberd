use std::ffi::{CStr, CString};
use std::slice;

extern "C" {
    #[link_name = "\u{1}_Z13base64_encodePKhmPcm"]
    pub fn base64_encode(
        source: *const ::std::os::raw::c_uchar,
        sourcelen: usize,
        target: *mut ::std::os::raw::c_char,
        targetlen: usize,
    ) -> ::std::os::raw::c_int;

    #[link_name = "\u{1}_Z13base64_decodePKcPhm"]
    pub fn base64_decode(
        source: *const ::std::os::raw::c_char,
        target: *mut ::std::os::raw::c_uchar,
        targetlen: usize,
    ) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_using_c_ffi(source: &[u8]) -> (i64, String) {
        let src_len = source.len();
        let dst_len = src_len / 3 * 4 + 10;
        let mut dest: Vec<i8> = Vec::with_capacity(dst_len);
        let success = unsafe {
            base64_encode(
                source.as_ptr() as *const u8,
                src_len,
                dest.as_mut_ptr() as *mut i8,
                dst_len,
            ) as i64
        };
        let encoded = unsafe {
            CStr::from_ptr(dest.as_ptr() as *const i8)
                .to_string_lossy()
                .into_owned()
        };
        (success, encoded)
    }

    fn decode_using_c_ffi(source: &str) -> Vec<u8> {
        let c_source = CString::new(source).unwrap();
        let dest_len = source.len() / 4 * 3 + 10;
        let mut dest: Vec<u8> = Vec::with_capacity(dest_len);
        let len =
            unsafe { base64_decode(c_source.as_ptr(), dest.as_mut_ptr() as *mut u8, dest_len) };
        let result = unsafe { slice::from_raw_parts(dest.as_mut_ptr(), len) };
        result.to_vec()
    }

    #[test]
    fn encodes_an_empty_array() {
        let empty_array: [u8; 0] = [];
        let (s, encoded) = encode_using_c_ffi(&empty_array);
        assert_eq!(encoded, String::from(""));
        assert_eq!(s, 1);
    }

    #[test]
    fn encodes_single_byte() {
        let single_byte_array: [u8; 1] = [0];
        let (s, encoded) = encode_using_c_ffi(&single_byte_array);
        assert_eq!(encoded, String::from("AA=="));
        assert_eq!(s, 1);
    }

    #[test]
    fn encodes_multiple_bytes() {
        let multi_byte_array: [u8; 3] = [0, 0x80, 0xFF];
        let (s, encoded) = encode_using_c_ffi(&multi_byte_array);
        assert_eq!(encoded, String::from("AID/"));
        assert_eq!(s, 1);
    }

    #[test]
    fn encodes_multiple_blocks() {
        let multi_byte_array: [u8; 5] = [10, 20, 30, 40, 50];
        let (s, encoded) = encode_using_c_ffi(&multi_byte_array);
        assert_eq!(encoded, String::from("ChQeKDI="));
        assert_eq!(s, 1);
    }

    #[test]
    fn decodes_empty_array() {
        let expected: [u8; 0] = [];
        assert_eq!(decode_using_c_ffi(""), expected);
    }

    #[test]
    fn decodes_single_bytes() {
        let expected: [u8; 1] = [0x4D];
        assert_eq!(decode_using_c_ffi("TQ=="), expected);
    }

    #[test]
    fn decodes_multiple_bytes() {
        let expected: [u8; 5] = [0, 16, 131, 16, 81];
        assert_eq!(decode_using_c_ffi("ABCDEFG="), expected);
    }
}
