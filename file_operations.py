# file_operations.py
import base64
import os
from crypto_utils import caesar_encrypt, caesar_decrypt, aes_encrypt, aes_decrypt

def execute_open_read(filepath: str, algorithm: str = None, session_key: str = None):
    """
    Handles 'openRead' command: Reads file content and returns it.
    Encrypts the text if an encryption algorithm is specified.
    Returns base64 text so it is safe to drop into a packet
    Returns (success, payload_or_error):

    success=True  -> payload_or_error is base64 text for a DP packet
    success=False -> payload_or_error is an already-formatted (EE,...) packet
    """
    if not os.path.exists(filepath):
        return False, "(EE,101,File Not Found)"
        
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
            
        # Unencrypted mode
        if not algorithm or algorithm.lower() == "none":
            payload = base64.b64encode(content.encode("utf-8")).decode("utf-8")
            return True, payload
            
        # Encrypted modes
        if algorithm.upper() == "AES":
            payload = aes_encrypt(content, session_key)
            return True, payload
        
        elif algorithm.capitalize() == "Caesar":
            shift = int(session_key) % 256
            payload = caesar_encrypt(content, shift)
            return True, payload
        
        else:
            return False, "(EE,102,Unsupported Encryption Algorithm)"
            
    except Exception as e:
        return False, f"(EE,500,Read Error: {str(e)})"


def execute_open_write(filepath: str, payload_text: str, algorithm: str = None, session_key: str = None) :
    """
    Handles 'openWrite' command + Data Packet writing:
    Payload text arrivesas base64 test, which we need to decode
    Decrypts payload if encryption was enabled, then saves content to file.

    Returns (success, message_or_error)
    """
    try:
        if not algorithm or algorithm.lower() == "none":
            raw_bytes = base64.b64decode(payload_text.encode("utf-8"))
            plain_text = raw_bytes.decode("utf-8")
 
        elif algorithm.upper() == "AES":
            plain_text = aes_decrypt(payload_text, session_key)
 
        elif algorithm.capitalize() == "Caesar":
            shift = int(session_key) % 256
            plain_text = caesar_decrypt(payload_text, shift)

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
    test_key = "77"
    # multi-line AND has a comma - exactly the kind of content that used
    # to break things before today's fix
    test_content = "Hello RFMP!\nThis is line two, with a comma.\nLine three."
 
    print("--- Unencrypted write & read (the content that used to break things) ---")
    with open(test_file, "w", encoding="utf-8") as f:
        f.write(test_content)
    success, payload = execute_open_read(test_file, algorithm=None)
    print("Read payload (base64):", payload)
    success, msg = execute_open_write(test_file, payload, algorithm=None)
    print("Write result:", msg)
 
    print("\n--- Caesar encrypted write & read ---")
    success, payload = execute_open_read(test_file, algorithm="Caesar", session_key=test_key)
    print("Encrypted payload:", payload)
    success, msg = execute_open_write(test_file, payload, algorithm="Caesar", session_key=test_key)
    print("Write result:", msg)
 
    os.remove(test_file)
    print("\nAll tests completed.")