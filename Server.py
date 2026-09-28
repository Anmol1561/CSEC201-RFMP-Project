# This is the server code of our RFMP project
# Currenlty we are establising a connection with the client and correctly recieve and read
# the Start-Packet. We will be developing the Encryption and file commands later, this is the basic code

import socket # This is a pyhton module that helps us to build connections

def sen_packet(connection, packet_str):
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

        if byte == b"\n" or byte == b"": # If the byte is a newline character or no byte is recienced due to some unexpected error, stop reading 
            break
        data  += byte # adds all the bytes so that we get the data

    return data.decode("utf-8") # this converts the raw bytes bback into readable string

def parse_packet(packet):
    """
    This function splits the string using comma as the delimeter and converts it into a list
    For example the string "(SS,RFMP,v1.0,0)" is converted into a list ["SS", RFMMP, "v1.0", "0"]
    This list makes the rest of the code simplew as now everything is an individual field
    """

    packet_content = packet.strip().strip("()") # removes the whitespace from starting and ending and then strips the parenthesis
    fields = packet_content.split(",") # splits it into pieces wherever there is comma

    cleaned_fields = [] # Creating and empty list
    for i in fields: # We go through fields using a for loop
        f = i.strip()
        cleaned_fields.append(f) # we add the cleaned stripped version of the fields into the blank list we created

    fields = cleaned_fields # Here the overwrite the old list with the clean one
    return fields

# Setting Up the Server

HOST = "localhost"
PORT = 2040

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#AF_INET means we are using IPv4 and SOCK_STREAM means we are using TCP

server_socket.bind((HOST,PORT)) 
server_socket.listen(1) #listening one connection at a time

connection, address = server_socket.accept()
print(f"A Client has been connected from {address}")

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

connection.close()
server_socket.close()
print("The connection has been closed")