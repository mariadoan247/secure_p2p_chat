import socket
import sys
import hashlib
from Crypto.Cipher import AES

# Initialize variables
host = 'localhost'
port = 8000
password = "password"
key = hashlib.sha256(password.encode()).digest()
cipher = AES.new(key, AES.MODE_EAX)

# Connect to the server
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    print("Connected to server")
except:
    print("Error connecting to server")
    sys.exit()

# Send initial message to establish connection
message = "Hello, server!"
ciphertext, tag = cipher.encrypt_and_digest(message.encode())
s.sendall(ciphertext + tag)

while True:
    # Receive message from server
    data = s.recv(1024)
    if not data:
        break

    # Decrypt message and print plaintext
    ciphertext = data[:-16]
    tag = data[-16:]
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    print("Server: " + plaintext.decode())

    # Send message to server
    message = input("You: ")
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    s.sendall(ciphertext + tag)

# Close the connection
s.close()
