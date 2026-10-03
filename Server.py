# This is the server code of our RFMP project
# Currenlty we are establising a connection with the client and correctly recieve and read
# the Start-Packet. We will be developing the Encryption and file commands later, this is the basic code

import base64
import math
import os
import random
import socket # This is a pyhton module that helps us to build connections
import subprocess # used to run the extra system commands (ls, whoami, ...)
import threading # used to serve many clients at the same time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def send_packet(connection, packet_str):
    """
    This send_packet funstion is used to send one packet over the connection
    
    connection = it is the socket connecftion object
    packet_str = It is basically the packet in form of a string. For eg "(SS,RFMO,v1.0,0)"
    """

    message = packet_str + "\n" # we add the  new line marker
    
    # We add the newline marker becayse in TCP protocol data is sent in raw stream of bytes so it does not know where the message ends
    #When we use newline we can use it as a marker or an identifier for the boundary so that the other side knows when to stop reaeding the message

    connection.sendall(message.encode("utf-8")) # This line will trun the text into byest and send it 

def recieve_packet(connection):
    """
    This function reads one message from the connection
    This function will read it one byte at a time until the newline character occurs in the send_packet function
    It will return the packet as a string"""

    data = b"" # this is an empty bytes object, we uild the message over here

    while True:
        byte = connection.recv(1) # In this while loop we first just collect one byte of data 

        if byte == b"\n" or byte == b"": # If the byte is a newline character or no byte is recieved due to some unexpected error, stop reading 
            break
        data  += byte # adds all the bytes so that we get the data

    return data.decode("utf-8") # this converts the raw bytes bback into readable string

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

#RSA IMPLEMENTATION- This section is responsible for handling key generation encryption and decryption using RSA

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
 
def rsa_decrypt(cipher_int, private_key):
    # This function decypts the message using the private key
    n, d = private_key # unpacks the private key into its two parts n and d
    return pow(cipher_int, d, n) # This part of RSA method is used to reverse the encryption


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


#File Operations

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
        return False, f"(EE,104,Read Error: {str(e)})"


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
        return False, f"(EE,104,Write Error: {str(e)})"
    
# ==========================================
# PROMPT COMMANDS + EXCEPTION PACKETS (Shubhi)
# ==========================================

# Exception packets (EE) - we use only 4 error codes (the maximum allowed)
#   101 -> File or folder not found
#   102 -> Invalid command (unknown command, missing argument, unsupported algorithm)
#   103 -> Invalid packet (malformed packet or unknown packet type)
#   104 -> Operation failed (access denied, already exists, folder not empty, read/write error)

def ee_packet(code, description):
    # builds an exception packet, e.g. (EE,101,Folder test not found)
    return f"(EE,{code},{description})"

def sc_packet(message):
    # builds a success packet, e.g. (SC,Folder test created)
    # packets are split on commas and end at a newline, so the message
    # cannot contain them (command output like ls has many lines)
    message = message.replace(",", ";").replace("\n", " | ")
    return f"(SC,{message})"

# Every client works inside this folder only, so a client cannot
# delete or read files anywhere else on the server computer
ROOT = os.path.abspath("server_files")
if not os.path.exists(ROOT):
    os.mkdir(ROOT)

def get_path(cwd, name):
    # joins the client's current folder with the name it sent
    # returns None if the path goes outside ROOT (for example "cd ../..")
    path = os.path.abspath(os.path.join(cwd, name))
    if path != ROOT and not path.startswith(ROOT + os.sep):
        return None
    return path

def show_path(path):
    # shows the folder relative to ROOT, e.g. /homework instead of the full path
    return path[len(ROOT):].replace(os.sep, "/") or "/"

# ----- required commands -----

def do_mkdir(cwd, args):
    if len(args) < 1:
        return ee_packet(102, "Usage: mkdir <folder>")
    path = get_path(cwd, args[0])
    if path is None:
        return ee_packet(104, "Access denied")
    if os.path.exists(path):
        return ee_packet(104, f"{args[0]} already exists")
    os.mkdir(path)
    return sc_packet(f"Folder {args[0]} created")

def do_rmdir(cwd, args):
    if len(args) < 1:
        return ee_packet(102, "Usage: rmdir <folder>")
    path = get_path(cwd, args[0])
    if path is None or path == ROOT:
        return ee_packet(104, "Access denied")
    if not os.path.isdir(path):
        return ee_packet(101, f"Folder {args[0]} not found")
    if len(os.listdir(path)) > 0:
        return ee_packet(104, f"Folder {args[0]} is not empty")
    os.rmdir(path)
    return sc_packet(f"Folder {args[0]} deleted")

def do_del(cwd, args):
    if len(args) < 1:
        return ee_packet(102, "Usage: del <file>")
    path = get_path(cwd, args[0])
    if path is None:
        return ee_packet(104, "Access denied")
    if not os.path.isfile(path):
        return ee_packet(101, f"File {args[0]} not found")
    os.remove(path)
    return sc_packet(f"File {args[0]} deleted")

def do_ren(cwd, args):
    if len(args) < 2:
        return ee_packet(102, "Usage: ren <old name> <new name>")
    old = get_path(cwd, args[0])
    new = get_path(cwd, args[1])
    if old is None or new is None:
        return ee_packet(104, "Access denied")
    if not os.path.exists(old):
        return ee_packet(101, f"{args[0]} not found")
    if os.path.exists(new):
        return ee_packet(104, f"{args[1]} already exists")
    os.rename(old, new)
    return sc_packet(f"Renamed {args[0]} to {args[1]}")

def do_cd(cwd, args):
    # cd changes the client's current folder, so it returns the reply AND the new folder
    if len(args) < 1:
        return sc_packet(show_path(cwd)), cwd # just "cd" shows the current folder
    path = get_path(cwd, args[0])
    if path is None:
        return ee_packet(104, "Access denied"), cwd
    if not os.path.isdir(path):
        return ee_packet(101, f"Folder {args[0]} not found"), cwd
    return sc_packet(f"Current folder: {show_path(path)}"), path

# ----- 5 extra system commands (run with subprocess.run) -----
# Only these commands are allowed, so a client cannot run
# something dangerous like "shutdown" on the server
if os.name == "nt": # Windows
    EXTRA_COMMANDS = {
        "ls":       ["cmd", "/c", "dir"],
        "whoami":   ["whoami"],
        "hostname": ["hostname"],
        "date":     ["cmd", "/c", "date /t"],
        "uptime":   ["cmd", "/c", "net statistics workstation"],
    }
else: # macOS / Linux
    EXTRA_COMMANDS = {
        "ls":       ["ls"],        # list the files in the current folder
        "whoami":   ["whoami"],    # user the server is running as
        "hostname": ["hostname"],  # name of the server computer
        "date":     ["date"],      # server date and time
        "uptime":   ["uptime"],    # how long the server has been on + CPU load
    }

def do_extra(cwd, name):
    try:
        # cwd=cwd runs the command inside this client's current folder
        result = subprocess.run(EXTRA_COMMANDS[name], cwd=cwd, capture_output=True,
                                text=True, timeout=5)
    except Exception:
        return ee_packet(104, f"{name} could not run on the server")
    if result.returncode != 0:
        return ee_packet(104, result.stderr.strip() or f"{name} failed")
    return sc_packet(result.stdout.strip() or "(empty)")

def run_prompt(cwd, command_text):
    """
    Runs one prompt command, e.g. "mkdir folder1" from (CM, prompt, mkdir folder1)
    Returns (reply packet, current folder) because cd can change the folder
    """
    parts = command_text.split()
    if len(parts) == 0:
        return ee_packet(102, "Empty command"), cwd
    command = parts[0].lower()
    args = parts[1:]

    try:
        if command == "cd":
            return do_cd(cwd, args)
        elif command == "mkdir":
            return do_mkdir(cwd, args), cwd
        elif command == "rmdir" or command == "rd":
            return do_rmdir(cwd, args), cwd
        elif command == "del":
            return do_del(cwd, args), cwd
        elif command == "ren":
            return do_ren(cwd, args), cwd
        elif command in EXTRA_COMMANDS:
            return do_extra(cwd, command), cwd
        else:
            return ee_packet(102, f"Unknown command {command}"), cwd
    except PermissionError:
        return ee_packet(104, "Permission denied"), cwd
    except Exception as e:
        return ee_packet(104, str(e).replace(",", ";")), cwd

# Setting Up the Server

HOST = "localhost"
PORT = 2040

# ==========================================
# MULTITHREADING (Shubhi)
# Each client gets its own thread, created using a class that
# inherits threading.Thread and overrides run()
# ==========================================

class ClientThread(threading.Thread):

    def __init__(self, connection, address):
        threading.Thread.__init__(self) # we override the constructor, so the base one must be called
        self.connection = connection
        self.address = address
        # each client has its OWN current folder (os.chdir would change it for every thread)
        self.cwd = ROOT

    def run(self):
        # start() runs this method in the new thread
        print(f"[{self.name}] A Client has been connected from {self.address}")
        try:
            self.handle_client(self.connection)
        except (ConnectionResetError, BrokenPipeError):
            print(f"[{self.name}] The client dropped the connection")
        except Exception as e:
            print(f"[{self.name}] Error: {e}")

        self.connection.close()
        print(f"[{self.name}] The connection has been closed")

    def handle_client(self, connection):
        # Setup phase, operation phase and closing phase for ONE client
        # (same steps as before, now running inside this client's thread)

        #Handling the start packet

        raw_packet = recieve_packet(connection) # This reads the eaw test
        print("Raw packet has been recieved:", raw_packet)

        fields = parse_packet(raw_packet) # we turn the raw packets into a list

        #  Pulling out each field from the list and assigning them name 
        packet_type = fields[0]   # should be "SS"
        protocol_name = fields[1]   # should be "RFMP"
        version = fields[2]   # should be "v1.0"
        secure_flag = fields[3]   # "0" = no encryption requested, "1" = encryption requested

        print(f"Packet type   : {packet_type}")
        print(f"Protocol  : {protocol_name} ")
        print(f"Version   : {version}")
        print(f"Secure flag   : {secure_flag}")

        # Handling the confirm-connection packet

        # when the secure flag is not 1 the algorithm, session key and server private key will be NONE

        algorithm = None
        encryption_key = None
        decryption_key = None

        # If the secure_flag is 0 we do not need encryption so its just a simple confirmation with no need of key
        if secure_flag == "0":
            send_packet(connection, "(CC)")
            print ("Sent: (CC)")
        else:
            server_publickey, server_privatekey = generate_rsa_keys() # We generate key pairs for this connection

            n,e = server_publickey #unpacking the numbers from the public key

            CC_packet = f"(CC,{n}:{e})" # This is the text that will be present in the packer

            send_packet(connection,CC_packet) # We send the packet to the client
            print("Sent:", CC_packet)

            decryption_key = server_privatekey

            #Handling the Encrypted Packet

            encrypted_packet = recieve_packet(connection) # This recieves the raw client's Encryption packet
            print(" A Raw Encrypted packet has been recieved from the client:", encrypted_packet)

            encrypted_packet_fields = parse_packet(encrypted_packet) # We call out the parse function and break down it into fields

            algorithm = encrypted_packet_fields[1] # checks the algoritm
            encrypted_key = int(encrypted_packet_fields[2]) # session key, parsed into an integer
            client_info = encrypted_packet_fields[3]

            encryption_key_int = rsa_decrypt(encrypted_key,decryption_key) # This will decrypt the encryption using our private key
            encryption_key = str(encryption_key_int) # converting it into a string

            print(f"Algorithm chosen: {algorithm}")
            print(f"Decrypted session key: {encryption_key}")
            print(f"Client info: {client_info}")

        # handling commands until the client sends "End"

        while True:
            raw_pkt = recieve_packet(connection) # waits for packet from the client

            if not raw_pkt:
                break # the loop is stopped if the connection breaks unexpectedly

            if raw_pkt.strip() == "End":
                print("Client is requestion for closing the connection")
                break

            fields = parse_packet(raw_pkt) # this will break the packets into fields

            if not fields:
                send_packet(connection, ee_packet(103, "Malformed Packet"))
                continue

            packet_type = fields[0] # indicates the packet type

            if packet_type == "CM":
                cmd_type = fields[1] #checks which command is it

                if len(fields) < 3: # every command needs an argument, e.g. (CM, prompt, ls)
                    send_packet(connection, ee_packet(102, "Missing argument"))
                    continue

                if cmd_type == "prompt": # prompt commands such as mkdir, cd, ren, ls
                    reply, self.cwd = run_prompt(self.cwd, fields[2]) # cd can change this client's folder
                    send_packet(connection, reply)

                elif cmd_type == "openRead":
                    file_name = fields[2]
                    file_path = get_path(self.cwd, file_name) # the file is opened inside this client's current folder

                    if file_path is None:
                        send_packet(connection, ee_packet(104, "Access denied"))
                        continue

                    success, result = execute_open_read(file_path, algorithm, encryption_key) # success means true or false and resultmens if it is a base64 payload or a formatted packet

                    if success:
                        send_packet(connection,f"(DP, {result})") # sends the file content as its own data packet
                        send_packet(connection,"(SC, Read Completed)") # Confirms the success

                    else:
                        send_packet(connection,result) # result in form of a packet string

                elif cmd_type == "openWrite":
                    file_name = fields[2] # This field tells which file do we have to write into
                    print(f"Server is ready to write into the file: {file_name}, waiting for teh data packet....")

                    raw_datapacket = recieve_packet(connection) # waiting for client to send the datapacket
                    datapacket_fields = parse_packet(raw_datapacket)

                    payload = datapacket_fields[1]
                    file_path = get_path(self.cwd, file_name) # the file is created inside this client's current folder

                    if file_path is None:
                        send_packet(connection, ee_packet(104, "Access denied"))
                        continue

                    success, result = execute_open_write(file_path, payload, algorithm, encryption_key)

                    if success:
                        send_packet(connection, result) # result is already an (SC,...) packet

                    else:
                        send_packet(connection, result) # result in form of a string packet

                else:
                    send_packet(connection, "(EE,102,Command could not be recognized)") # command type is unknown

            else:
                send_packet(connection,"(EE,103,Unknown Packet type)") # packet_type wasnt CM, DP or End


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#AF_INET means we are using IPv4 and SOCK_STREAM means we are using TCP
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # lets us restart the server straight away

server_socket.bind((HOST,PORT))
server_socket.listen(5) # up to 5 clients can wait in the queue to be accepted
print(f"RFMP server is listening on port {PORT}, files are kept in {ROOT}")

try:
    while True:
        connection, address = server_socket.accept() # the main thread waits for a new client
        client_thread = ClientThread(connection, address)
        client_thread.daemon = True # client threads stop when the server stops
        client_thread.start()
        # no join() here, otherwise the server would serve only one client at a time
        print("Active clients:", threading.active_count() - 1) # minus 1 for the main thread
except KeyboardInterrupt:
    print("\nServer is shutting down")

server_socket.close()
