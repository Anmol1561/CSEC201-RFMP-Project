# This is the client side code of our ZRFMP project

import socket

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

#Connecting the client to the server

HOST = "localhost"
PORT = 2040

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #AF_INET is for ipv4 and SOCK_STREAM is for tcp
client_socket.connect((HOST, PORT))   # this actually opens the connection to the server
print("Connected to server.")

packet_type   = "SS"
protocol_name = "RFMP"
version       = "v1.0"
secure_flag   = "0"   
 

start_packet = f"({packet_type},{protocol_name},{version},{secure_flag})"
print("Sending:", start_packet)
 
send_packet(client_socket, start_packet)
 
client_socket.close()
print("Packet sent, connection closed.")