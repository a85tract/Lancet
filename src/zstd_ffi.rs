use std::ffi::{c_uint, c_ulonglong, c_void};
use std::io;

#[link(name = "zstd")]
unsafe extern "C" {
    fn ZSTD_compressBound(srcSize: usize) -> usize;
    fn ZSTD_compress(
        dst: *mut c_void,
        dstCapacity: usize,
        src: *const c_void,
        srcSize: usize,
        compressionLevel: i32,
    ) -> usize;
    fn ZSTD_decompress(
        dst: *mut c_void,
        dstCapacity: usize,
        src: *const c_void,
        compressedSize: usize,
    ) -> usize;
    fn ZSTD_isError(code: usize) -> c_uint;
    fn ZSTD_getFrameContentSize(src: *const c_void, srcSize: usize) -> c_ulonglong;
}

pub fn compress(data: &[u8], level: i32) -> io::Result<Vec<u8>> {
    unsafe {
        let bound = ZSTD_compressBound(data.len());
        let mut out = vec![0u8; bound];
        let written = ZSTD_compress(
            out.as_mut_ptr().cast(),
            out.len(),
            data.as_ptr().cast(),
            data.len(),
            level,
        );
        if ZSTD_isError(written) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "zstd compress failed",
            ));
        }
        out.truncate(written);
        Ok(out)
    }
}

pub fn decompress(data: &[u8], uncompressed_size: usize) -> io::Result<Vec<u8>> {
    unsafe {
        let _frame_size = ZSTD_getFrameContentSize(data.as_ptr().cast(), data.len());
        let mut out = vec![0u8; uncompressed_size];
        let written = ZSTD_decompress(
            out.as_mut_ptr().cast(),
            out.len(),
            data.as_ptr().cast(),
            data.len(),
        );
        if ZSTD_isError(written) != 0 || written != uncompressed_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "zstd decompress failed",
            ));
        }
        Ok(out)
    }
}
