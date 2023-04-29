import socket
import hashlib
import threading
from Crypto.Cipher import AES
import os

# Define server IP address and port number
SERVER_IP = '127.0.0.1'
SERVER_PORT = 5000

# Define the password for key generation
PASSWORD = 'mysecretpassword'

# Define the block size for AES encryption
BLOCK_SIZE = 16

# Define the iteration count for key derivation function
ITERATION_COUNT = 100000

# Define the salt for key derivation function
SALT = b'salt'

# Define the secret key for AES encryption
SECRET_KEY = None

# Define the initialization vector for AES encryption
IV = None

# Define the server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the server socket to the IP address and port number
server_socket.bind((SERVER_IP, SERVER_PORT))

# Listen for incoming connections
server_socket.listen()

print(f"Server is listening on {SERVER_IP}:{SERVER_PORT}")

# Generate the secret key from the password
def generate_secret_key(password):
    global SECRET_KEY
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), SALT, ITERATION_COUNT)
    SECRET_KEY = key[:16]
    print("THIS IS THE SECRET KEY: ", SECRET_KEY)

# Generate the initialization vector for AES encryption
def generate_iv():
    global IV
    IV = os.urandom(BLOCK_SIZE)
    print("THIS IS THE IV: ", IV)

# Encrypt the message using AES encryption
def encrypt_message(message):
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
    padded_message = message + (BLOCK_SIZE - len(message) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(message) % BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded_message.encode('utf-8'))
    print("THIS IS THE CIPHERTEXT: ", ciphertext)
    return IV + ciphertext

# Decrypt the message using AES encryption
def decrypt_message(ciphertext_with_iv):
    iv = ciphertext_with_iv[:BLOCK_SIZE]
    ciphertext = ciphertext_with_iv[BLOCK_SIZE:]
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = padded_plaintext[:-padded_plaintext[-1]].decode('latin-1')
    print("THIS IS THE PLAINTEXT: ", plaintext)
    return plaintext

# Handle client connections
def handle_client(client_socket):
    # Receive the password from the client
    password = client_socket.recv(1024).decode('utf-8')
    print(f"Received password from client: {password}")
    
    # Generate the secret key from the password
    generate_secret_key(PASSWORD)
    
    # Generate the initialization vector for AES encryption
    generate_iv()
    
    while True:
        # Receive the ciphertext from the client
        ciphertext_with_iv = client_socket.recv(1024)
        if not ciphertext_with_iv:
            break
        # Decrypt the ciphertext and print the plaintext
        plaintext = decrypt_message(ciphertext_with_iv)
        print(f"Received message from client: {plaintext}")
        
        # Encrypt a response message and send it to the client
        response_message = input("Enter response: ")
        response_ciphertext = encrypt_message(response_message)
        client_socket.send(response_ciphertext)

        generate_secret_key(SECRET_KEY.decode('latin-1'))
    
    # Close the client socket
    client_socket.close()
    print("Client disconnected")

# Accept incoming connections and spawn a new thread to handle each client
while True:
    client_socket, client_address = server_socket.accept()
    print(f"Client connected: {client_address}")
    client_thread = threading.Thread(target=handle_client, args=(client_socket,))
    client_thread.start()
