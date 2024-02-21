import socket
import pyDes
import time
from key import key_C, key_Tgs

SERVER_ADDRESS = '127.0.0.1'
SERVER_PORT = 8000
SHARED_KEY = key_C
AS_TGS_KEY = key_Tgs
des_decryptor = pyDes.des(SHARED_KEY, pyDes.ECB, pad=None, padmode=pyDes.PAD_PKCS5)
des_encryptor_as_tgs = pyDes.des(AS_TGS_KEY, pyDes.ECB, pad=None, padmode=pyDes.PAD_PKCS5)

# Create a socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to an address and port
server_socket.bind((SERVER_ADDRESS, SERVER_PORT))

# Start listening for incoming connections
server_socket.listen(5)
print(f"Server listening on {SERVER_ADDRESS}:{SERVER_PORT}")

try:
    while True:
        # Accept incoming connections from clients
        client_socket, client_address = server_socket.accept()
        print(f"Accepted connection from {client_address}")

        # Receive data from clients
        encrypted_data = client_socket.recv(1024)
        if not encrypted_data:
            break

        # Step 1: Print out the received message on the AS side
        print("Step (1): Received message on the AS side:")
        print(f"Received message: {encrypted_data}")

        # Decrypt the data
        decrypted_data = des_decryptor.decrypt(encrypted_data)
        print(f"Decrypted data from the client: {decrypted_data}")

        # Extract client ID and timestamp
        client_id, timestamp = decrypted_data.decode().split('||')

        # Perform an ID check for 𝐼𝐷!
        if client_id != "CIS3319USERID":
            print("Step 1: 𝐼𝐷! mismatch. Authentication terminated.")
            break

        # Generate a TGT (Ticket Granting Ticket)
        tgt_data = f"TGT||{client_id}||{SERVER_ADDRESS}||{int(time.time()) + 120}"  # Valid for 60 seconds
        encrypted_tgt = des_encryptor_as_tgs.encrypt(tgt_data)

        print(f"Generated TGT: {encrypted_tgt}")

        # Send the encrypted TGT back to the client
        client_socket.sendall(encrypted_tgt)

        # Close the client socket
        client_socket.close()

except KeyboardInterrupt:
    print("\nServer is shutting down.")

except Exception as e:
    print(f"Error: {e}")

finally:
    # Close the server socket
    server_socket.close()
    print("Server socket closed.")



