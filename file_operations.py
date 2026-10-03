# file_operations.py
import os
import base64
from crypto_utils import caesar_encrypt, caesar_decrypt, aes_encrypt, aes_decrypt

def execute_open_read(filepath: str, algorithm: str = None, session_key: str = None) -> tuple[bool, str]:
    """
    Handles 'openRead' command: Reads file content and returns raw/encrypted payload.
    Error returns keep (EE,code,msg) format, success returns raw payload string.
    """
    if not os.path.exists(filepath):
        return False, "(EE,3,File Not Found)"
        
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
            
        # 1. Unencrypted mode (Base64 encode raw content to avoid breaking delimiters)
        if not algorithm or algorithm.lower() == "none":
            b64_payload = base64.b64encode(content.encode("utf-8")).decode("utf-8")
            return True, b64_payload
            
        # Determine Caesar shift from session_key if provided
        shift = int(session_key) % 256 if session_key and session_key.isdigit() else 3

        # 2. Encrypted modes
        if algorithm.upper() == "AES":
            encrypted_data = aes_encrypt(content, session_key)
            return True, encrypted_data
        elif algorithm.capitalize() == "Caesar":
            encrypted_data = caesar_encrypt(content, shift)
            return True, encrypted_data
        else:
            return False, "(EE,4,Unsupported Encryption Algorithm)"
            
    except Exception as e:
        return False, f"(EE,4,Read Error: {str(e)})"


def execute_open_write(filepath: str, payload_text: str, algorithm: str = None, session_key: str = None) -> tuple[bool, str]:
    """
    Handles 'openWrite' command: Decrypts payload/Base64 and writes content to file.
    Returns (True, "File written successfully") or (False, "(EE,code,msg)").
    """
    try:
        # Determine Caesar shift from session_key if provided
        shift = int(session_key) % 256 if session_key and session_key.isdigit() else 3

        # Decrypt / Decode payload
        if not algorithm or algorithm.lower() == "none":
            plain_text = base64.b64decode(payload_text.encode("utf-8")).decode("utf-8")
        elif algorithm.upper() == "AES":
            plain_text = aes_decrypt(payload_text, session_key)
        elif algorithm.capitalize() == "Caesar":
            plain_text = caesar_decrypt(payload_text, shift)
        else:
            return False, "(EE,4,Unsupported Encryption Algorithm)"

        # Write content to destination file
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(plain_text)
            
        return True, "File written successfully"
        
    except Exception as e:
        return False, f"(EE,4,Write Error: {str(e)})"


# ==========================================
# LOCAL TEST BLOCK
# ==========================================
if __name__ == "__main__":
    test_file = "test_rfmp.txt"
    test_key = "123456"  # Numeric key for session key testing
    test_content = "Hello RFMP Protocol!\nThis file contains commas, and newlines."

    print("--- 1. Testing Unencrypted Write & Read ---")
    # Read/Write without encryption (Base64 encoded payload)
    b64_content = base64.b64encode(test_content.encode("utf-8")).decode("utf-8")
    success, res_w = execute_open_write(test_file, b64_content, algorithm="none")
    print("Write Result:", res_w)
    
    success, raw_payload = execute_open_read(test_file, algorithm="none")
    decoded_content = base64.b64decode(raw_payload.encode("utf-8")).decode("utf-8")
    print("Read Payload (Base64):", raw_payload)
    print("Decoded Content:", decoded_content)
    assert decoded_content == test_content, "Unencrypted test failed!"

    print("\n--- 2. Testing Caesar Encrypted Read/Write with Session Key ---")
    # Test Caesar shift generated from session key
    shift_val = int(test_key) % 256
    enc_caesar = caesar_encrypt(test_content, shift_val)
    success, res_cw = execute_open_write(test_file, enc_caesar, algorithm="Caesar", session_key=test_key)
    print("Caesar Write Result:", res_cw)
    
    success, caesar_payload = execute_open_read(test_file, algorithm="Caesar", session_key=test_key)
    dec_caesar = caesar_decrypt(caesar_payload, shift_val)
    assert dec_caesar == test_content, "Caesar key shift test failed!"
    print("Caesar Read/Decrypt Successful!")

    # Clean up test file
    if os.path.exists(test_file):
        os.remove(test_file)

    print("\n✅ All updated file operation tests completed successfully!")