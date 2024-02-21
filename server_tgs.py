import socket
import pyDes
import time
from key import key_Ctgs, k_V

TGS_ADDRESS = '127.0.0.1'
TGS_PORT = 8001
TGS_KEY = key_Ctgs
SERVICE_KEY = k_V
validity_period = 60  # Validity period of the service ticket, assumed to be 60 seconds
des_decryptor_tgs = pyDes.des(TGS_KEY, pyDes.ECB, pad=None, padmode=pyDes.PAD_PKCS5)
des_encryptor_service = pyDes.des(SERVICE_KEY, pyDes.ECB, pad=None, padmode=pyDes.PAD_PKCS5)

# Create a socket
tgs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to an address and port
tgs_socket.bind((TGS_ADDRESS, TGS_PORT))

# Start listening for incoming connections
tgs_socket.listen(5)
print(f"TGS listening on {TGS_ADDRESS}:{TGS_PORT}")

try:
    while True:
        # Accept incoming connections from clients
        client_socket, client_address = tgs_socket.accept()
        print(f"Accepted connection from {client_address}")

        # Receive data
        encrypted_data = client_socket.recv(1024)
        if not encrypted_data:
            break

        # Print the received message
        print("Step (3): Received message on TGS side:")
        print(f"Received message: {encrypted_data}")

        # Decrypt the data
        decrypted_data = des_decryptor_tgs.decrypt(encrypted_data)
        print(f"Decrypted data from the client: {decrypted_data}")

        # Split the data, with the last element being the TGT
        split_data = decrypted_data.decode().split('||')
        user_id, service_id, timestamp = split_data[:3]
        tgt = '||'.join(split_data[3:])

        # Validate the TGT and timestamp
        current_time = int(time.time())
        tgt_data = tgt
        split_tgt = tgt_data.split('||')
        if len(split_tgt) != 4 or split_tgt[0] != "TGT":
            print("Invalid TGT. Authentication terminated.")
        else:
            tgt_user_id = split_tgt[1]
            tgt_tgs_address = split_tgt[2]
            tgt_timestamp = int(split_tgt[3])

            if tgt_user_id != "CIS3319USERID" or tgt_tgs_address != TGS_ADDRESS:
                print("Invalid TGT user ID or TGS address. Authentication terminated.")
            elif current_time - tgt_timestamp > validity_period:
                print("TGT has expired. Authentication terminated.")
            else:
                print("TGT is valid. Generating a service ticket...")

        # Generate a service ticket
        validity_period = 120  # Validity period of the service ticket, assumed to be 60 seconds
        service_ticket = f"ST||{user_id}||{service_id}||{int(time.time()) + validity_period}"
        encrypted_service_ticket = des_encryptor_service.encrypt(service_ticket)

        # Send the service ticket back to the client
        client_socket.sendall(encrypted_service_ticket)

        # Close the client socket
        client_socket.close()

except KeyboardInterrupt:
    print("\nTGS is shutting down.")

except Exception as e:
    print(f"Error: {e}")

finally:
    # Close the TGS socket
    tgs_socket.close()
    print("TGS socket closed.")

