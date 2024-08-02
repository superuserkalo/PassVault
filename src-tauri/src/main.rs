#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::error::Error;
use aes_gcm::{Aes256Gcm, Key, KeyInit};
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::rand_core::RngCore;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use rusqlite::{Connection, params};
use tauri::InvokeError;

// Learn more about Tauri commands at https://tauri.app/v1/guides/features/command
fn hash_credentials(master_key: &str) -> Result<String, Box<dyn Error>> {
    // Generate a unique salt for the master key
    let master_key_salt: SaltString = SaltString::generate(&mut OsRng);

    let argon2: Argon2 = Argon2::default();

    // Hash the master key with the generated salt
    let master_key_hash = argon2.hash_password(master_key.as_bytes(), &master_key_salt).expect("Failed to hash master_key").to_string();

    Ok(master_key_hash)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![initialize_app, login_hash_comparison])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");

}

#[tauri::command]
fn initialize_app(master_key: String) -> Result<String, String> {
    println!("initialize_app called with master_key: {}", master_key);
    
    let master_key_hash = hash_credentials(&master_key)
        .map_err(|e| format!("Hashing credentials failed: {:?}", e))?;
    println!("Master key hash generated: {}", master_key_hash);
    
    let (encrypted_master_key_hash, key_nonce) = encrypt(master_key_hash.as_bytes())
        .map_err(|e| format!("Encryption failed: {:?}", e))?;
    println!("Encrypted master key hash and nonce generated");

    initialize_database(encrypted_master_key_hash, key_nonce)
        .map_err(|e| format!("Database initialization failed: {:?}", e))?;
    println!("Database initialized successfully");

    Ok("Vault created successfully".to_string())
}

#[tauri::command]
fn login_hash_comparison(master_key: &str) -> Result<bool, InvokeError>{
    let db_path: &str = "vault.db";
    let conn: Connection = Connection::open(db_path).map_err(|e| e.to_string())?;

    let (db_encrypted_master_key_hash, db_key_nonce): (Vec<u8>, Vec<u8>) = conn.query_row(
        "SELECT encrypted_master_key_hash, key_nonce FROM master",
        [],
        |row| Ok((row.get(0)?, row.get(1)?))
    ).map_err(|e| e.to_string())?;

    let db_decrypted_master_key_hash = decrypt(
        &db_encrypted_master_key_hash,
        db_key_nonce.as_slice().try_into().map_err(|_| "Invalid nonce size".to_string())?
    ).map_err(|e| format!("Master key decryption error: {:?}", e))?;

    let db_master_key_hash = std::str::from_utf8(&db_decrypted_master_key_hash)
        .map_err(|e| e.to_string())?;

    let db_master_key_hash = PasswordHash::new(db_master_key_hash)
        .map_err(|e| format!("Invalid master key hash: {}", e))?;

    let argon2 = Argon2::default();

    let master_key_verification = argon2.verify_password(master_key.as_bytes(), &db_master_key_hash).is_ok();

    Ok(master_key_verification)
}


pub const KEY_SIZE: usize = 32; // AES-256 key size in bytes
pub const NONCE_SIZE: usize = 12; // Nonce size for AES-GCM

pub fn generate_aes_key() -> [u8; KEY_SIZE] {
    [0u8; KEY_SIZE]
}

pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);

    nonce
}

// Encrypt plaintext using AES-GCM with a given key and nonce and return ciphertext
pub fn encrypt(plaintext: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_SIZE]), aes_gcm::Error> {
    let key = generate_aes_key();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let nonce = generate_nonce();
    let ciphertext = cipher.encrypt(GenericArray::from_slice(&nonce), plaintext)?;
    Ok((ciphertext, nonce))
}
// Decrypt ciphertext using AES-GCM with a given key and nonce and return plaintext
pub fn decrypt(ciphertext: &[u8], nonce: &[u8; NONCE_SIZE]) -> Result<Vec<u8>, aes_gcm::Error> {
    let key = generate_aes_key();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let plaintext = cipher.decrypt(GenericArray::from_slice(nonce), ciphertext)?;
    Ok(plaintext)
}

pub fn initialize_database(encrypted_master_key_hash: Vec<u8>, key_nonce: [u8; NONCE_SIZE]) -> Result<(), Box<dyn Error>> {
    let db_path: &str = "vault.db";
    let conn: Connection = Connection::open(db_path)?;

    conn.execute(
        "
        CREATE TABLE IF NOT EXISTS master (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_master_key_hash BLOB NOT NULL,
            key_nonce BLOB NOT NULL
        )
        ",
        [],
    )?;

    conn.execute(
        "
        INSERT INTO master (encrypted_master_key_hash, key_nonce) VALUES (?1, ?2)
        ",
        params![encrypted_master_key_hash, key_nonce],
    )?;

    Ok(())
}

