import socket
import hashlib
from Crypto.Cipher import AES
import os
import threading
import tkinter as tk
from tkinter import messagebox

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

# Handle server responses
def handle_response():
    global client_socket
    while True:
        # Receive the ciphertext from the server
        ciphertext_with_iv = client_socket.recv(1024)
        if not ciphertext_with_iv:
            break
        
        # Decrypt the ciphertext and print the plaintext
        plaintext = decrypt_message(ciphertext_with_iv)
        print(f"Received message from server: {plaintext}")
        messagebox.showinfo("Message from Server", f"{plaintext}")

# Connect to the server and start a new thread to handle server responses
def connect_to_server():
    global client_socket
    global password_entry
    global message_entry
    global send_button
    global connect_button
    global disconnect_button
    
    # Get the password from the password entry widget
    password = password_entry.get()
    
    # Generate the secret key from the password
    generate_secret_key(password)
    
    # Generate the initialization vector for AES encryption
    generate_iv()
    
    # Connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))
    
    # Send the password to the server
    client_socket.send(password.encode('utf-8'))
    
    # Disable the password entry and connect button, and enable the message entry and send button
    password_entry.config(state='disabled')
    connect_button.config(state='disabled')
    message_entry.config(state='normal')
    send_button.config(state='normal')
    disconnect_button.config(state='normal')
    
    # Start a new thread to handle server responses
    response_thread = threading.Thread(target=handle_response)
    response_thread.start()

# Disconnect from the server and reset the GUI
def disconnect_from_server():
    global client_socket
    global password_entry
    global message_entry
    global send_button
    global connect_button
    global disconnect_button
    
    # Send a message to the server indicating that the client is disconnecting
    client_socket.send("DISCONNECT".encode('utf-8'))
    
    # Close the client socket
    client_socket.close()
    
    # Enable the password entry and connect button, and disable the message entry and send button
    password_entry.config(state='normal')
    connect_button.config(state='normal')
    message_entry.delete(0, 'end')
    message_entry.config(state='disabled')
    send_button.config(state='disabled')
    disconnect_button.config(state='disabled')

# Send a message to the server
def send_message():
    global client_socket
    global message_entry
    
    # Get the message from the message entry widget
    message = message_entry.get()
    
    # Encrypt the message using AES encryption
    ciphertext = encrypt_message(message)
    
    # Send the ciphertext to the server
    client_socket.send(ciphertext)

    # Clear the message entry widget
    message_entry.delete(0, 'end')

# Create the GUI
root = tk.Tk()
root.title("Client")

# Create the password label and entry widgets
password_label = tk.Label(root, text="Password:")
password_label.grid(row=0, column=0, sticky="w")
password_entry = tk.Entry(root, show="*")
password_entry.grid(row=0, column=1)

# Create the message label and entry widgets
message_label = tk.Label(root, text="Message:")
message_label.grid(row=1, column=0, sticky="w")
message_entry = tk.Entry(root, state='disabled')
message_entry.grid(row=1, column=1)

# Create the send button widget
send_button = tk.Button(root, text="Send", command=send_message, state='disabled')
send_button.grid(row=1, column=2)

# Create the connect button widget
connect_button = tk.Button(root, text="Connect", command=connect_to_server)
connect_button.grid(row=2, column=0)

# Create the disconnect button widget
disconnect_button = tk.Button(root, text="Disconnect", command=disconnect_from_server, state='disabled')
disconnect_button.grid(row=2, column=1)

# Run the GUI
root.mainloop()

