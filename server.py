import socket
import threading
from Crypto.Cipher import AES

# Chiave segreta condivisa tra client e server
SECRET_KEY = b"0123456789abcdef"
AUTH_KEY = "supersegreta"  # Chiave di autenticazione

def decrypt_data(data):
    """Decifra i dati ricevuti dal client"""
    nonce = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext)

def handle_client(client_socket, addr):
    print(f"Connessione accettata da {addr}")

    try:
        # Riceve la chiave di autenticazione
        auth_key = client_socket.recv(1024).decode().strip()
        if auth_key != AUTH_KEY:
            print(f"❌ Connessione rifiutata da {addr}: chiave errata!")
            client_socket.send(b"Autenticazione fallita!")
            client_socket.close()
            return

        client_socket.send(b"Autenticazione riuscita!")

        while True:
            encrypted_data = client_socket.recv(4096)
            if not encrypted_data:
                break

            # Decripta il messaggio
            data = decrypt_data(encrypted_data)
            print(f"Ricevuto da {addr}: {data.decode()}")

            # Risposta
            client_socket.send(b"Messaggio ricevuto dal server")
    except Exception as e:
        print(f"Errore con {addr}: {e}")

    client_socket.close()

def start_vpn_server(host="0.0.0.0", port=8080):
    """Avvia il server VPN"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"Server VPN in ascolto su {host}:{port}")

    while True:
        client_socket, addr = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_handler.start()

if __name__ == "__main__":
    start_vpn_server()
