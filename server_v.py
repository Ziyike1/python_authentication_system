import socket
import pyDes
import time
from key import key_Cv

V_ADDRESS = '127.0.0.1'
V_PORT = 8002
SERVICE_KEY = key_Cv
des_decryptor_service = pyDes.des(SERVICE_KEY, pyDes.ECB, pad=None, padmode=pyDes.PAD_PKCS5)

# Create a socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind to the address and port of the service server (V)
server_socket.bind((V_ADDRESS, V_PORT))

# Start listening
server_socket.listen()

print(f"V listening on {V_ADDRESS}:{V_PORT}")

# Accept client connections
client_socket, client_address = server_socket.accept()
print(f"Accepted connection from {client_address}")

try:
    # Receive and decrypt the client's service request
    encrypted_service_request = client_socket.recv(1024)
    decrypted_service_request = des_decryptor_service.decrypt(encrypted_service_request)
    print(f"Received message: {encrypted_service_request}")
    print(f"Decrypted service request from the client: {decrypted_service_request}")

    # Check the legitimacy of the service request
    service_request = decrypted_service_request.decode()
    split_data = service_request.split('||')
    if len(split_data) != 4 or split_data[0] != "Service Request":
        print("Invalid service request. Authentication terminated.")
    else:
        user_id = split_data[1]
        service_id = split_data[2]
        timestamp = int(split_data[3])

        # Add timestamp validity check
        current_time = int(time.time())
        if current_time - timestamp > 120:
            print("Service request timestamp has expired. Authentication terminated.")
        elif user_id != "CIS3319USERID" or service_id != "CIS3319SERVERID":
            print("Invalid user ID or service ID. Authentication terminated.")
        else:
            print("Service request is valid. Generating a service ticket...")

    # Create a service ticket (ST)
    service_ticket = f"Service Ticket||CIS3319USERID||CIS3319SERVERID||{int(time.time())}"
    encrypted_service_ticket = des_decryptor_service.encrypt(service_ticket)

    # Send the service ticket to the client
    client_socket.sendall(encrypted_service_ticket)
    print("Service ticket sent to the client")

except Exception as e:
    print(f"An error occurred: {e}")

# Close the socket connections
client_socket.close()
server_socket.close()
