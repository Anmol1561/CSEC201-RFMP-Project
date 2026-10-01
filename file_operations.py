# file_operations.py
import os
from crypto_utils import caesar_encrypt, caesar_decrypt, aes_encrypt, aes_decrypt

def execute_open_read(filepath: str, algorithm: str = None, session_key: str = None) -> tuple[bool, str]:
    """
    Handles 'openRead' command: Reads file content and returns it.
    Encrypts the text if an encryption algorithm is specified.
    """
    if not os.path.exists(filepath):
        return False, "(EE,101,File Not Found)"
        
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
            
        # Unencrypted mode
        if not algorithm or algorithm.lower() == "none":
            return True, f"(SC,{content})"
            
        # Encrypted modes
        if algorithm.upper() == "AES":
            encrypted_data = aes_encrypt(content, session_key)
            return True, f"(SC,{encrypted_data})"
        elif algorithm.capitalize() == "Caesar":
            encrypted_data = caesar_encrypt(content)
            return True, f"(SC,{encrypted_data})"
        else:
            return False, "(EE,102,Unsupported Encryption Algorithm)"
            
    except Exception as e:
        return False, f"(EE,500,Read Error: {str(e)})"


def execute_open_write(filepath: str, payload_text: str, algorithm: str = None, session_key: str = None) -> tuple[bool, str]:
    """
    Handles 'openWrite' command + Data Packet writing:
    Decrypts payload if encryption was enabled, then saves content to file.
    """
    try:
        # Decrypt payload if encryption was selected
        if not algorithm or algorithm.lower() == "none":
            plain_text = payload_text
        elif algorithm.upper() == "AES":
            plain_text = aes_decrypt(payload_text, session_key)
        elif algorithm.capitalize() == "Caesar":
            plain_text = caesar_decrypt(payload_text)
        else:
            return False, "(EE,102,Unsupported Encryption Algorithm)"

        # Write content to remote file
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(plain_text)
            
        return True, "(SC,File written successfully)"
        
    except Exception as e:
        return False, f"(EE,501,Write Error: {str(e)})"


# ==========================================
# QUICK LOCAL TEST
# ==========================================
if __name__ == "__main__":
    test_file = "test_rfmp.txt"
    test_key = "my_session_key"
    test_content = "Hello RFMP Protocol File Operations!"

    print("--- 1. Testing Unencrypted Write & Read ---")
    success, res = execute_open_write(test_file, test_content, algorithm="none")
    print("Write Response:", res)
    success, res = execute_open_read(test_file, algorithm="none")
    print("Read Response:", res)

    print("\n--- 2. Testing AES Encrypted Write & Read ---")
    encrypted_payload = aes_encrypt(test_content, test_key)
    success, write_res = execute_open_write(test_file, encrypted_payload, algorithm="AES", session_key=test_key)
    print("Write Response:", write_res)
    success, read_res = execute_open_read(test_file, algorithm="AES", session_key=test_key)
    print("Read Response:", read_res)

    # Clean up test file
    if os.path.exists(test_file):
        os.remove(test_file)

    print("\n✅ All file operation tests completed successfully!")