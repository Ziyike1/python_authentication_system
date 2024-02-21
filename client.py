import socket
import time
import pyDes

from key import key_C, key_Ctgs

AS_ADDRESS = '127.0.0.1'
AS_PORT = 8000
TGS_ADDRESS = '127.0.0.1'
TGS_PORT = 8001
V_ADDRESS = '127.0.0.1'
V_PORT = 8002
SHARED_KEY_AS = key_C
TGS_SESSION_KEY = key_Ctgs
des_encryptor_as = pyDes.des(SHARED_KEY_AS, pyDes.ECB, pad=None, padmode=pyDes.PAD_PKCS5)
des_encryptor_tgs = pyDes.des(TGS_SESSION_KEY, pyDes.ECB, pad=None, padmode=pyDes.PAD_PKCS5)
des_decryptor_as = pyDes.des(SHARED_KEY_AS, pyDes.ECB, pad=None, padmode=pyDes.PAD_PKCS5)


# Create authentication request
def create_auth_request(user_id):
    timestamp = int(time.time())
    message = f"{user_id}||{timestamp}"
    encrypted_message = des_encryptor_as.encrypt(message)
    return encrypted_message


# Create TGS request
def create_tgs_request(user_id, service_id, tgt):
    timestamp = int(time.time())
    tgt_data = tgt.decode()
    message = f"{user_id}||{service_id}||{timestamp}||{tgt_data}"
    encrypted_message = des_encryptor_tgs.encrypt(message)
    return encrypted_message


# Create service request
def create_service_request(user_id, service_id):
    timestamp = int(time.time()) + 1  # Add 1 second to simulate the client requesting a service
    message = f"Service Request||{user_id}||{service_id}||{timestamp}"
    encrypted_message = des_encryptor_tgs.encrypt(message)
    return encrypted_message


# Create a socket to connect to AS
client_socket_as = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # Connect to AS
    client_socket_as.connect((AS_ADDRESS, AS_PORT))
    print(f"Connected to AS at {AS_ADDRESS}:{AS_PORT}")

    # Send authentication request
    auth_request = create_auth_request("CIS3319USERID")
    client_socket_as.sendall(auth_request)

    # Receive and decrypt AS's reply (TGT)
    encrypted_tgt = client_socket_as.recv(1024)
    decrypted_tgt = des_decryptor_as.decrypt(encrypted_tgt)
    print(f"Step (2): Plaintext on C side: {encrypted_tgt}")
    print(f"Decrypted TGT from AS: {decrypted_tgt}")

    # Close the connection to AS
    client_socket_as.close()

    # Create a socket to connect to TGS
    client_socket_tgs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket_tgs.connect((TGS_ADDRESS, TGS_PORT))
    print(f"Connected to TGS at {TGS_ADDRESS}:{TGS_PORT}")

    # Send TGS request
    tgs_request = create_tgs_request("CIS3319USERID", "CIS3319SERVERID", decrypted_tgt)
    client_socket_tgs.sendall(tgs_request)

    # Receive and decrypt TGS's reply (service ticket)
    encrypted_service_ticket = client_socket_tgs.recv(1024)
    decrypted_service_ticket = des_encryptor_tgs.decrypt(encrypted_service_ticket)
    print(f"Step (4): Plaintext and 𝑇𝑖𝑐𝑘𝑒𝑡V on C side:{encrypted_service_ticket}")
    print(f"Decrypted service ticket from TGS: {decrypted_service_ticket}")

    # Close the connection to TGS
    client_socket_tgs.close()

    # Create a socket to connect to the service server (V)
    client_socket_v = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the service server (V)
    client_socket_v.connect((V_ADDRESS, V_PORT))
    print(f"Connected to V at {V_ADDRESS}:{V_PORT}")

    # Send service request
    service_request = create_service_request("CIS3319USERID", "CIS3319SERVERID")
    client_socket_v.sendall(service_request)

    # Receive and decrypt the response from the service server (V)
    encrypted_response = client_socket_v.recv(1024)
    decrypted_response = des_decryptor_as.decrypt(encrypted_response)
    print(f"Encrypted response from V: {encrypted_response}")
    print(f"Decrypted response from V: {decrypted_response}")

    # Close the connection to the service server (V)
    client_socket_v.close()

except Exception as e:
    print(f"An error occurred: {e}")
