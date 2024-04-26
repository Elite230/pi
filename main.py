import socket
import threading
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

# Diffie-Hellman parameters
parameters = dh.generate_parameters(generator=2, key_size=2048)
private_key = parameters.generate_private_key()

def handle_client(client_socket):
    # Perform Diffie-Hellman key exchange
    client_public_key = client_socket.recv(2048)
    client_public_key = serialization.load_pem_public_key(client_public_key)
    shared_key = private_key.exchange(client_public_key)

    # Now you have a shared secret key for encryption

    # Chat logic (you can expand this)
    while True:
        message = client_socket.recv(1024).decode()
        if not message:
            break
        # Process the message (e.g., encrypt using shared_key)
        print(f"Received: {message}")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind(("0.0.0.0", 12345))
    server_socket.listen(5)
    print("Server listening on port 12345...")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")
        client_socket.sendall(parameters.parameter_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()
