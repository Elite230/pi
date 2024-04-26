import socket
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

# Diffie-Hellman parameters (same as server)
parameters = dh.generate_parameters(generator=2, key_size=2048)
private_key = parameters.generate_private_key()

def perform_diffie_hellman(server_public_key):
    shared_key = private_key.exchange(server_public_key)
    return shared_key

def main():
    host = "127.0.0.1"  # Change this to the server's IP address
    port = 12345

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        print(f"Connected to {host}:{port}")

        # Receive server's Diffie-Hellman public key
        server_public_key = client_socket.recv(2048)
        server_public_key = serialization.load_pem_public_key(server_public_key)

        # Perform Diffie-Hellman key exchange
        shared_key = perform_diffie_hellman(server_public_key)

        # Now you have a shared secret key for encryption

        # Chat logic (you can expand this)
        while True:
            message = input("Enter your message: ")
            client_socket.sendall(message.encode())
            if message.lower() == "exit":
                break

            # Process received messages (e.g., decrypt using shared_key)
            response = client_socket.recv(1024).decode()
            print(f"Received: {response}")

if __name__ == "__main__":
    main()
