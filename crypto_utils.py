# crypto_utils.py
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ==========================================
# 1. CAESAR CIPHER
# ==========================================

def caesar_encrypt(text: str, shift: int = 3) -> str:
    """Encrypts text using a byte-wise Caesar shift and Base64 encodes it."""
    data = text.encode('utf-8')
    encrypted_bytes = bytes([(b + shift) % 256 for b in data])
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def caesar_decrypt(cipher_text_b64: str, shift: int = 3) -> str:
    """Decrypts Base64 encoded Caesar cipher text back to plain text."""
    data = base64.b64decode(cipher_text_b64.encode('utf-8'))
    decrypted_bytes = bytes([(b - shift) % 256 for b in data])
    return decrypted_bytes.decode('utf-8')


# ==========================================
# 2. AES CIPHER (CBC Mode)
# ==========================================

def aes_encrypt(text: str, key: str) -> str:
    """Encrypts text using AES-128 CBC mode. Returns Base64 string of IV + Ciphertext."""
    key_bytes = key.encode('utf-8').ljust(16, b'\x00')[:16]
    data_bytes = text.encode('utf-8')
    
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    padded_data = pad(data_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    combined = cipher.iv + ciphertext
    return base64.b64encode(combined).decode('utf-8')

def aes_decrypt(cipher_text_b64: str, key: str) -> str:
    """Decrypts Base64 AES-CBC payload back to plain text."""
    key_bytes = key.encode('utf-8').ljust(16, b'\x00')[:16]
    combined = base64.b64decode(cipher_text_b64.encode('utf-8'))
    
    iv = combined[:16]
    ciphertext = combined[16:]
    
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
    padded_data = cipher.decrypt(ciphertext)
    return unpad(padded_data, AES.block_size).decode('utf-8')


# ==========================================
# QUICK LOCAL TEST
# ==========================================
if __name__ == "__main__":
    test_msg = "Hello CSEC-201 RFMP!"
    secret_key = "my_session_key"

    print("--- Testing Caesar Cipher ---")
    caesar_enc = caesar_encrypt(test_msg)
    caesar_dec = caesar_decrypt(caesar_enc)
    print("Encrypted:", caesar_enc)
    print("Decrypted:", caesar_dec)
    assert test_msg == caesar_dec, "Caesar test failed!"

    print("\n--- Testing AES Cipher ---")
    aes_enc = aes_encrypt(test_msg, secret_key)
    aes_dec = aes_decrypt(aes_enc, secret_key)
    print("Encrypted:", aes_enc)
    print("Decrypted:", aes_dec)
    assert test_msg == aes_dec, "AES test failed!"

    print("\n✅ All cipher tests passed successfully!")