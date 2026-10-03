# This is the client side code of our ZRFMP project

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



#Connecting the client to the server

HOST = "localhost"
PORT = 2040

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #AF_INET is for ipv4 and SOCK_STREAM is for tcp
client_socket.connect((HOST, PORT))   # this actually opens the connection to the server
print("Connected to server.")

packet_type   = "SS"
protocol_name = "RFMP"
version       = "v1.0"
secure_flag   = "0"   # change this to 1 if you have to test the encrypted path
 

start_packet = f"({packet_type},{protocol_name},{version},{secure_flag})"
print("Sending:", start_packet)
 
send_packet(client_socket, start_packet)

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
    print(f"Server's public key: {server_publickey}")

    #Generating public and private key for the cleint side
    client_publickey, client_privatekey = generate_rsa_keys()

    algorithm = "Caesar" # algorithm we are telling the server to use
    encryption_key_int = 77
    encryption_key = str(encryption_key_int) # converting the interger to string

    # Encrypting the session using server's public key so only server can decrypt it using its privaye key
    encrypted_key = rsa_encrypt(encryption_key_int,server_publickey)

    username = "anmol"
    cn , ce = client_publickey # unpacking our own public key to include in packet

    ec_packet = f"(EC,{algorithm},{encrypted_key},{username}:{cn}:{ce})"
    print("Sending:", ec_packet)
    send_packet(client_socket, ec_packet)

# Doing openRead testthen decrypt/decode the response

cm_packet = "(CM,openRead,testfile.txt)" # building  a command packet for reading the file
print("Sending:", cm_packet)
send_packet(client_socket, cm_packet)

dp_raw = recieve_packet(client_socket) #The server will respond with the file content 
print("Received Data Packet:", dp_raw)

sc_raw = recieve_packet(client_socket) #then a separate success confirmation message will be shown
print("Received:", sc_raw)

# Pulling the payload out of the DP packet and then decrypt it if a cipher is used or else jsut base-64 decode it

dp_fields = parse_packet(dp_raw) #breaking it into fields
received_payload = dp_fields[1]

if algorithm == "AES":
    original_text = aes_decrypt(received_payload, encryption_key)

elif algorithm == "Caesar":
    shift = int(encryption_key) % 256   # same shift math the server used
    original_text = caesar_decrypt(received_payload, shift)

else:
    # unencrypted mode - still base64, just decode it, no cipher involved
    original_text = base64.b64decode(received_payload.encode("utf-8")).decode("utf-8")
 
print("Actual decoded file content:", original_text)

# Testing openWrite, taking new text encrypting it(or just encode if encryption is off)
# So server can handle it properly and then sends the actual content over

new_content = "New content from the client!"

if algorithm == "AES":
    payload_to_send = aes_encrypt(new_content, encryption_key)

elif algorithm == "Caesar":
    shift = int(encryption_key) % 256
    payload_to_send = caesar_encrypt(new_content, shift)

else:
    payload_to_send = base64.b64encode(new_content.encode("utf-8")).decode("utf-8")

write_cmd_packet = "(CM,openWrite,testfile.txt)"
print("Sending:", write_cmd_packet)
send_packet(client_socket, write_cmd_packet)
 
data_packet = f"(DP,{payload_to_send})"
print("Sending:", data_packet)
send_packet(client_socket, data_packet)
 
write_response = recieve_packet(client_socket)
print("Received:", write_response)


# Prompt Command, listing the content of the server's folder

prompt_packet = "(CM,prompt,ls)"
print("Sending:", prompt_packet)
send_packet(client_socket, prompt_packet)
 
prompt_response = recieve_packet(client_socket)
print("Received:", prompt_response)

send_packet(client_socket, "End")
 
client_socket.close()
print("Packet sent, connection closed.")