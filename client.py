import socket
from Crypto.Cipher import AES

# Chiave segreta AES (deve essere la stessa del server)
SECRET_KEY = b"0123456789abcdef"

def encrypt_data(data):
    """Cifra i dati prima di inviarli al server"""
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX)
    return cipher.nonce + cipher.encrypt(data)

def connect_to_vpn(server_ip="127.0.0.1", server_port=8080):
    """Si connette al server VPN"""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((server_ip, server_port))
    print(f"Connesso a {server_ip}:{server_port}")

    while True:
        message = input("Messaggio da inviare: ")
        encrypted_message = encrypt_data(message.encode())

        client.send(encrypted_message)
        response = client.recv(4096)
        print(f"Risposta del server: {response.decode()}")

if __name__ == "__main__":
    connect_to_vpn()
