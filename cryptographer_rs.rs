// cryptographer_rs.rs — криптограф (шифрование файлов) на Rust

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use rand::RngCore;
use std::fs::File;
use std::io::{Read, Write};
use std::env;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const ITERATIONS: u32 = 100000;
const KEY_LEN: usize = 32;

fn derive_key(password: &[u8], salt: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password, salt, ITERATIONS, &mut key);
    key
}

fn encrypt_file(input: &str, output: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut plaintext = Vec::new();
    File::open(input)?.read_to_end(&mut plaintext)?;

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    let key = derive_key(password.as_bytes(), &salt);
    let cipher = Aes256Gcm::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce);
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;

    let mut out = File::create(output)?;
    out.write_all(&salt)?;
    out.write_all(&nonce)?;
    out.write_all(&ciphertext)?;
    println!("Файл зашифрован: {}", output);
    Ok(())
}

fn decrypt_file(input: &str, output: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut data = Vec::new();
    File::open(input)?.read_to_end(&mut data)?;
    if data.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
        return Err("Некорректный зашифрованный файл".into());
    }
    let salt = &data[0..SALT_LEN];
    let nonce = &data[SALT_LEN..SALT_LEN+NONCE_LEN];
    let ciphertext = &data[SALT_LEN+NONCE_LEN..];

    let key = derive_key(password.as_bytes(), salt);
    let cipher = Aes256Gcm::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher.decrypt(nonce, ciphertext)?;

    let mut out = File::create(output)?;
    out.write_all(&plaintext)?;
    println!("Файл расшифрован: {}", output);
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("Использование: {} <encrypt|decrypt> <input> <output> <password>", args[0]);
        std::process::exit(1);
    }
    let mode = &args[1];
    let input = &args[2];
    let output = &args[3];
    let password = &args[4];

    match mode.as_str() {
        "encrypt" => encrypt_file(input, output, password)?,
        "decrypt" => decrypt_file(input, output, password)?,
        _ => {
            eprintln!("Режим должен быть encrypt или decrypt");
            std::process::exit(1);
        }
    }
    Ok(())
}
