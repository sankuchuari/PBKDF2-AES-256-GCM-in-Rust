use std::fs::File;
use std::io::ErrorKind;
use std::io::{self, Read, Write, BufReader, BufRead};
use sha2::{Sha256, Digest};
use pbkdf2::pbkdf2;
use hmac::Hmac;
use rand::{Rng};
use hex::{encode, decode};
use rand_core::{RngCore};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};

//使用 PBKDF2 对文本进行加密（salt）和散列（hash）运算 (Encrypt (salt) and hash text using PBKDF2.)
const PBKDF2_ITERATIONS: u32 = 100_000; //设置 PBKDF2 的迭代次数 (Set the number of iterations for PBKDF2.)
const SALT_LENGTH: usize = 16; // 盐的长度 (length of salt)
const NONCE_LENGTH: usize = 12;
// 生成随机盐 （Generating Random Salt）
fn generate_salt() -> Vec<u8> {
    let mut rng = rand::rng();
    let mut salt = vec![0u8; SALT_LENGTH];
    rng.fill(&mut salt[..]);
    salt
}
// 使用 PBKDF2 派生出 32 字节密钥 (Use PBKDF2 to derive 32-byte keys)
fn pbkdf2_hash(password: &str, salt: &[u8]) -> Vec<u8> {
    let mut output = vec![0u8; 32];
    // 这里 unwrap 是因为 pbkdf2 返回 ()
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut output).unwrap();
    output
}
// 加密函数
fn encrypt_data(password: &str, plaintext: &[u8]) -> (String, String, String) {
    let salt = generate_salt(); // salt 生成函数 
    let key_bytes = pbkdf2_hash(password, &salt); // PBKDF2 派生函数

    // 显式指定 key 类型 (Specify key type explicitly)
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));

    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    rand::rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .expect("encryption failure!");

    (
        encode(&salt),
        encode(&nonce_bytes),
        encode(&ciphertext),
    )
}
// 解密函数 (decrypt function)
fn decrypt_data(
    password: &str,
    salt_hex: &str,
    nonce_hex: &str,
    ct_hex: &str
) -> Result<Vec<u8>, aes_gcm::Error> {
    let salt        = decode(salt_hex).expect("invalid salt hex");
    let nonce_bytes = decode(nonce_hex).expect("invalid nonce hex");
    let ciphertext  = decode(ct_hex).expect("invalid ciphertext hex");

    let key_bytes = pbkdf2_hash(password, &salt);

    // 显式指定 key 类型 (Specify key type explicitly)
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce  = Nonce::from_slice(&nonce_bytes);
    
    cipher.decrypt(nonce, ciphertext.as_ref())
}


// 使用 AES-256-GCM 加密文件内容 (Encrypting File Contents with AES-256-GCM)
fn encrypt_file(path: &str, password: &str, out_path: &str) -> io::Result<()> {
    let mut file = File::open(path)?;
    let mut plaintext = Vec::new();
    file.read_to_end(&mut plaintext)?;

    // 盐 + 密钥生成 (Salt + Key Generation)
    let salt = generate_salt();
    let mut key_bytes = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), &salt, PBKDF2_ITERATIONS, &mut key_bytes).unwrap();
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes); //  显式指定类型

    // Nonce 生成 (Nonce Generation)
    let mut nonce_bytes = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes); //  12字节 nonce

    // 加密 (encrypted)
    let cipher = Aes256Gcm::new(key);
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).expect("加密失败 encryption failure");

    // 输出到文件：salt + nonce + ciphertext  (Output to file: salt + nonce + ciphertext)
    let mut output = File::create(out_path)?;
    output.write_all(&salt)?;
    output.write_all(&nonce_bytes)?;
    output.write_all(&ciphertext)?;

    Ok(())
}
//解密文件内容 (Decrypting the contents of a file)
fn decrypt_file(enc_path: &str, password: &str, out_path: &str) -> io::Result<()> {
    let mut file = File::open(enc_path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    // 检查内容长度是否合法 (Check for legal content length)
    if contents.len() < SALT_LENGTH + NONCE_LENGTH {
        return Err(io::Error::new(ErrorKind::InvalidData, "加密文件格式错误 Encrypted file format error"));
    }

    // 提取 salt (前 16 字节) (Extract salt (first 16 bytes) )
    let salt = &contents[..SALT_LENGTH];
    // 提取 nonce (接下来的 12 字节) (Extract nonce (next 12 bytes) )
    let nonce_bytes = &contents[SALT_LENGTH..SALT_LENGTH + NONCE_LENGTH];
    // 剩下的是密文 (The rest is ciphertext.)
    let ciphertext = &contents[SALT_LENGTH + NONCE_LENGTH..];

    // 派生密钥 (derived key)
    let mut key_bytes = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key_bytes).unwrap();
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

    // 初始化 AES-GCM (Initialise AES-GCM)
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    // 解密密文 (decrypted dense text)
    let decrypted_data = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "解密失败：密码错误或数据损坏 Decryption failed: wrong password or corrupted data"))?;

    // 写入输出文件 (Write to output file)
    let mut output_file = File::create(out_path)?;
    output_file.write_all(&decrypted_data)?;

    println!("解密成功 Decryption succeeded：{}", out_path);
    Ok(())
}


//计算并返回SHA265 (Calculates and returns SHA265)
fn calculate_sha256(file_path: &str) -> io::Result<String> {
    // 打开文件 (Open file)
    let mut file = File::open(file_path)?;

    // 创建 SHA-256 哈希计算器 (Creating a SHA-256 Hash Calculator)
    let mut hasher = Sha256::new();

    // 读取文件并更新哈希值 (Read the file and update the hash)
    let mut buffer = [0u8; 8192]; // 读取缓冲区 (readout buffer)
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    // 获取 SHA-256 哈希值并以十六进制字符串格式返回  (Gets the SHA-256 hash value and returns it as a hexadecimal string)
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}


//文本文件操作 (Text File Operations)
fn operate(text:&str,path:&str,enc_path:&str,dec_path:&str,password:&str){
    //打开文件
    File::open(path).unwrap_or_else(|e| {
        if e.kind() == ErrorKind::NotFound {
            File::create(path).unwrap_or_else(|error| {
                panic! ("创建文件时发生问题 Problems with file creation：{:?}", error);
            })
        } else {
            panic! ("打开文件时出现问题 Problems opening files：{:?}", e);
        }
    });
    //加密内容 (Encrypted content)
    let (salt_hex, nonce_hex, ct_hex) = encrypt_data(password, text.as_ref());
    //写入文件 (Write to file)
    let mut output = File::create(path).unwrap();
    write!(output, "{}\n{}\n{}", salt_hex,nonce_hex,ct_hex).expect("写入文件时发生问题 Problems writing to files");
    // 对文件进行加密 (Encrypting file)
    if let Err(e) = encrypt_file(path, password, enc_path) {
        eprintln!("文件加密失败 File encryption failed: {:?}", e);
    } else {
        println!("文件已加密，保存为 File encrypted.Save as: {}", enc_path);
    }
    //输出文件SHA265 (Output file SHA265)
    match calculate_sha256(enc_path) {
        Ok(hash) => println!("SHA-256: {}", hash),
        Err(e) => eprintln!("Error calculating SHA-256: {}", e),
    }
    // 对加密后的文件进行解密 (Decrypting encrypted files)
    if let Err(e) = decrypt_file(enc_path, password, dec_path) {
        eprintln!("文件解密失败 File decryption failed: {:?}", e);
    } else {
        println!("文件已解密，保存为 File decrypted.Save as: {}", dec_path);
    }
    //提取文件并解密 (Extract and decrypt files)
    let input = File::open(dec_path).unwrap();
    let buffered = BufReader::new(input);
    let mut enc_v=Vec::new();
    for line in buffered.lines() {
        let s: String = line.unwrap();
        enc_v.push(s);
        
    }
    match decrypt_data(password, &enc_v[0], &enc_v[1], &enc_v[2]) {
        Ok(pt) => println!("解密成功，明文 Decryption successful, plaintext: {}", String::from_utf8_lossy(&pt)),
        Err(e) => eprintln!("解密失败 Decryption failed: {:?}", e),
    }
}
fn main() {
    //文本 (text)
    let my_text="Sankuchuari";
    //设定地址 (Setting address)
    let path = "hello.txt"; //原始文件路径 (Path to original file)
    let enc_path = "hello.enc"; //加密后的文件保存路径 (Path to the encrypted file)
    let dec_path = "hello_dec.txt"; // 解密后的文件保存路径 (Path to the decrypted file)
    let password = "my_password"; //密钥 (key)
    operate(my_text,path,enc_path,dec_path,password);
}