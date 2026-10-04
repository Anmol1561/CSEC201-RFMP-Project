# RFMP (Remote File Management Protocol) - Python client
# Group members: 
# Anmol Preet Singh
# Ahmed Elshennawy
# Aditya Kadhi
# Shubhi Attal

import base64
import math
import random
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def send_packet(connection, packet_str):
    """
    send_packet function is used to send packet over the connection
    
    connection : is the socket connection object
    packet_str : is the pacjet in form of a string"""

    message = packet_str +"\n" #Adding newline charcter at end so recienving side knows where this packet stops
    connection.sendall(message.encode("utf-8")) # this will turn the text into bytes

def recieve_packet(connection):
    """
    Returns the pacjet byte by byte and returns it in the form of a string
    """

    data = b"" # a empty bytes object
    while True:
        byte = connection.recv(1) #We recieve one byte at a time
        if byte == b"\n" or byte == b"": # if byte is a newline character or it is not recieved stop reading
            break
        data += byte # add all the bytes 

    return data.decode("utf-8") # converts the raw bytes into readable string

def parse_packet(packet):
    """
    This function splits the string using comma as the delimeter and converts it into a list
    For example the string "(SS,RFMP,v1.0,0)" is converted into a list ["SS", RFMMP, "v1.0", "0"]
    This list makes the rest of the code simple as now everything is an individual field
    """
    packet_content = packet.strip().strip("()") # removes the whitespace from starting and ending and then strips the parenthesis
    fields = packet_content.split(",") # splits it into pieces wherever there is comma
    
    cleaned_fields = [] # Creating and empty list
    for i in fields: # We go through fields using a for loop
        f = i.strip()
        cleaned_fields.append(f) # we add the cleaned stripped version of the fields into the blank list we created

    fields = cleaned_fields # Here the overwrite the old list with the clean one
    return fields

#RSA IMPLEMENTATION- This section is responsible for handling key generation encryption using RSA

def egcd(a, b):
    # This is Extended Euclidean Algorithm 
    # It finds gcd(a, b)  and the two coefficients needed to build a modular inverse in modinv() below.
    if b == 0:
        return a, 1, 0  
    g, x1, y1 = egcd(b, a % b) 
    return g, y1, x1 - (a // b) * y1  
 
def modinv(a, m): # This finds the modular inverse
    # Finds x such that (a * x) % m == 1.
    # This turns the public exponent e into the private exponent d.
    g, x, _ = egcd(a, m)
    if g != 1:
        return None
    return x % m                
 
def is_prime(n):
    # This checks if a number is prime or not
    if n < 2:
        return False # 0 and 1 aren't prime
    for i in range(2, int(math.sqrt(n)) + 1):          
        if n % i == 0:
            return False
    return True
 
def generate_prime():
    # This function is used to generate a random prime number
    while True: # keep trying until we succeed
        p = random.randint(100, 300)  # picks a random number between 100 and 300
        if is_prime(p): # Call the is_prime function for confirmation of prime and then returns it
            return p 
 
def generate_rsa_keys():
    # This function is used to generate RSA public and private keys

    # We generate 2 random prime numbers p and q 
    # p and q cannot be the same number
    p = generate_prime()
    q = generate_prime()

    while q == p: # This while loop helps us to get different prime numbers
        q = generate_prime()

    #Calculating n and phi which is used in RSA math

    n = p * q # n is used in both public and private keys
    phi = (p - 1) * (q - 1) # phi is known as Euler's totient and is needed to compute d 
 
    e = 65537 # This is the standard public exponent

    #if the standard value of e does not work we work with smaller values
    if math.gcd(e, phi) != 1:
        e = 3
 
    d = modinv(e, phi) # Generates the private key
 
    public_key = (n,e) # this is the public key
    private_key = (n,d) # this is the private key
    
    return public_key, private_key
 
def rsa_encrypt(message_int, public_key):
    # This function encryps the message using the public key
    n, e = public_key # unpacks the public key into it two parts n and e
    return pow(message_int, e, n) # This is the RSA math, (message ^ e) modulus n


# Symmetric Ciphers

# ==========================================
# 1. CAESAR CIPHER
# ==========================================

def caesar_encrypt(text: str, shift: int = 3) -> str: 
    """Encrypts text using a byte-wise Caesar shift and Base64 encodes it."""
    data = text.encode('utf-8') # converts the plain text into raw UTF-8 bytes
    encrypted_bytes = bytes([(b + shift) % 256 for b in data]) #Applying byte-level Caesar shift modulo 256
    return base64.b64encode(encrypted_bytes).decode('utf-8') #base64 encoding encrypted bytes and returning the string

def caesar_decrypt(cipher_text_b64: str, shift: int = 3) -> str:
    """Decrypts Base64 encoded Caesar cipher text back to plain text."""
    data = base64.b64decode(cipher_text_b64.encode('utf-8')) # Decode base64 string back to encrypted byte array
    decrypted_bytes = bytes([(b - shift) % 256 for b in data]) # Reversing byte-level Caesar shift modulo 25
    return decrypted_bytes.decode('utf-8') # decoded decrypted bytes back to string

# ==========================================
# 2. AES CIPHER (CBC Mode)
# ==========================================

def aes_encrypt(text: str, key: str) -> str:
    """Encrypts text using AES-128 CBC mode. Returns Base64 string of IV + Ciphertext."""
    key_bytes = key.encode('utf-8').ljust(16, b'\x00')[:16] # Formatting symmetric key string into 16-byte byte key
    data_bytes = text.encode('utf-8') # encoding plain text into UTF-8 bytes
    
    cipher = AES.new(key_bytes, AES.MODE_CBC) # Creating new AES cipher object which is configured for CBC mode
    padded_data = pad(data_bytes, AES.block_size) # Padding the plain text bytes to align with AES 16 bytes block size
    ciphertext = cipher.encrypt(padded_data) # encrypting the padded bytes with AES cipher
    
    combined = cipher.iv + ciphertext # concatenating header with ciphertext payload bytes
    return base64.b64encode(combined).decode('utf-8') # base64 encode combined bytes and return string

def aes_decrypt(cipher_text_b64: str, key: str) -> str:
    """Decrypts Base64 AES-CBC payload back to plain text."""
    key_bytes = key.encode('utf-8').ljust(16, b'\x00')[:16] # Formatting key string to 16 bytes
    combined = base64.b64decode(cipher_text_b64.encode('utf-8')) # Base64 decodes the cipher string into raw bytes
    
    iv = combined[:16] # extracting initial 16 bytes
    ciphertext = combined[16:] # remaining bytes
    
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv) # inititalising AES cipher object
    padded_data = cipher.decrypt(ciphertext) # Decrypt ciphertext bytes into padded bytes
    return unpad(padded_data, AES.block_size).decode('utf-8') # unpading the bytes and decode it to a string



#Connecting the client to the server

HOST = "localhost"
PORT = 2040

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #AF_INET is for ipv4 and SOCK_STREAM is for tcp
client_socket.connect((HOST, PORT))   # this actually opens the connection to the server
print("Connected to server.")

packet_type   = "SS" # defines the start packet
protocol_name = "RFMP" # defines the prototcol name
version       = "v1.0" # prototcol version string

secure_choice = input("Connect securely? (y/n): ").strip().lower() # asks the user for secured or unsecured connection
secure_flag = "1" if secure_choice == "y" else "0"
 

start_packet = f"({packet_type},{protocol_name},{version},{secure_flag})" # constructing the start packet string
print("Sending:", start_packet) # printing the constructed start packet
 
send_packet(client_socket, start_packet) # sends the start packet over the socket

#Recieving the confirm-connection packet

cc_raw = recieve_packet(client_socket) # waiting for server's response
print("Recieved:", cc_raw)
fields_cc = parse_packet(cc_raw) # breaking the confirm connection packet into fields

algorithm = None
encryption_key = None
# These will stay none unless the secure flag = 1

if secure_flag =="1":
    n_str , e_str = fields_cc[1].split(":") # This will split the first field of confirm connection packet i.e the key into n and e using : as the delimetre
    server_publickey = (int(n_str), int(e_str)) # converts n and e to numbers
    print(f"Server's public key: {server_publickey}") # Prints the  server's public key

    #Generating public and private key for the cleint side
    client_publickey, client_privatekey = generate_rsa_keys()

    algorithm_choice = input("Which algorithm - AES or Caesar? ").strip()
    algorithm = "AES" if algorithm_choice.upper() == "AES" else "Caesar"
    encryption_key_int = 77 # Session secretkey integer value
    encryption_key = str(encryption_key_int) # converting the interger to string

    # Encrypting the session using server's public key so only server can decrypt it using its privaye key
    encrypted_key = rsa_encrypt(encryption_key_int,server_publickey) 

    username = "anmol" # setting client username
    cn , ce = client_publickey # unpacking our own public key to include in packet

    ec_packet = f"(EC,{algorithm},{encrypted_key},{username}:{cn}:{ce})"
    print("Sending:", ec_packet)
    send_packet(client_socket, ec_packet)

# ============================================================
# INTERACTIVE LOOP 
# ============================================================

print("\n=== RFMP Client ===")
print("Commands:")
print("  read <filename>          - read a file from the server")
print("  write <filename>         - write new content to a file on the server")
print("  <anything else>          - sent as a system command, e.g: mkdir test / cd test / ls / whoami")
print("  quit                     - close the connection\n")

while True:
    user_input = input("> ").strip()

    if not user_input: # if user leaves it blanks and press enter iteration will be skipped
        continue

    if user_input.lower() in ("quit", "exit"): # terminates the loop if user types quit or exit
        break

    if user_input.startswith("read "): # used for reading the file name 
        filename = user_input[5:].strip() # we extract the file name after 5 characters as user will type read <filename>
        send_packet(client_socket, f"(CM,openRead,{filename})") # sending command packet request to the server
        response = recieve_packet(client_socket) # recieves teh server response

        if response.strip().startswith("(EE"):
            print("Server error:", response) # displays error  if server returns exception packet

        else:
            confirm = recieve_packet(client_socket)   # the separate (SC,Read Completed) packet
            dp_fields = parse_packet(response) # breaks the response packet into fields
            payload = dp_fields[1] # extracts the raw payload from data packet fields list

            if algorithm == "AES": # executing AED decryption on payload
                text = aes_decrypt(payload, encryption_key)

            elif algorithm == "Caesar": # decrypting the Caesar cipher if used
                shift = int(encryption_key) % 256
                text = caesar_decrypt(payload, shift)

            else:
                text = base64.b64decode(payload.encode("utf-8")).decode("utf-8") # decoding plain base64 payload

            print("--- File content ---")
            print(text)
            print("--------------------")

    elif user_input.startswith("write "):
        filename = user_input[6:].strip() # extracts the filename from the sixth character because user will enter write <filename>
        content = input("Enter the content to write: ")

        # following the same steps which we did in openRead
        if algorithm == "AES":
            payload = aes_encrypt(content, encryption_key)
        elif algorithm == "Caesar":
            shift = int(encryption_key) % 256
            payload = caesar_encrypt(content, shift)
        else:
            payload = base64.b64encode(content.encode("utf-8")).decode("utf-8")

        send_packet(client_socket, f"(CM,openWrite,{filename})") # sending command packet for openWrite operation
        send_packet(client_socket, f"(DP,{payload})") # sending the datapacket
        response = recieve_packet(client_socket) # recieving the server response
        print("Server:", response) # printing the server response

    else:
        # anything else gets sent straight through as a system command -
        # covers mkdir, cd, rmdir, del, ren, and the 5 extra commands
        send_packet(client_socket, f"(CM,prompt,{user_input})")
        response = recieve_packet(client_socket)
        print("Server:", response)


send_packet(client_socket, "End") # sends close session packet to the server
client_socket.close() # closes the connection
print("Connection closed.")