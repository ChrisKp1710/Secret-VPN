import socket
import threading
import hashlib
import json
import os
from Crypto.Cipher import AES

USER_DB_FILE = "users.db"
SECRET_KEY = b"0123456789abcdef"

def load_users():
    if not os.path.exists(USER_DB_FILE):
        return {}
    with open(USER_DB_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USER_DB_FILE, "w") as f:
        json.dump(users, f)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def decrypt_data(data):
    nonce = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode()

def handle_client(client_socket, addr):
    print(f"Connessione accettata da {addr}")

    try:
        action = client_socket.recv(1024).decode().strip()
        encrypted_creds = client_socket.recv(4096)
        credentials = decrypt_data(encrypted_creds)
        username, password = credentials.split("|")

        users = load_users()
        hashed_password = hash_password(password)

        if action == "register":
            if username in users:
                client_socket.send("Errore: Username già registrato!".encode('utf-8'))
                client_socket.close()
                return
            users[username] = hashed_password
            save_users(users)
            client_socket.send(b"Registrazione completata! Ora puoi fare il login.")
        elif action == "login":
            if username not in users or users[username] != hashed_password:
                client_socket.send(b"Autenticazione fallita!")
                client_socket.close()
                return
            client_socket.send(b"Autenticazione riuscita!")
        else:
            client_socket.send(b"Azione non valida!")
            client_socket.close()
            return

        while True:
            encrypted_data = client_socket.recv(4096)
            if not encrypted_data:
                break

            data = decrypt_data(encrypted_data)
            if data.strip() == "/exit":
                print(f"🔌 {username} si è disconnesso correttamente.")
                client_socket.send(b"Disconnessione riuscita.")
                client_socket.close()
                break

            print(f"Ricevuto da {username} ({addr}): {data}")
            client_socket.send(b"Messaggio ricevuto dal server")
    except Exception as e:
        print(f"Errore con {addr}: {e}")

    client_socket.close()

def start_vpn_server(host="0.0.0.0", port=8080):
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
