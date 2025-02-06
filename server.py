import socket
import sys
import threading
import hashlib
import json
import os
from Crypto.Cipher import AES

USER_DB_FILE = "users.db"
SECRET_KEY = b"0123456789abcdef"
server_running = True  

# Dizionario per tenere traccia degli utenti connessi
connected_clients = {}

# Definizione colori ANSI
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"

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

def broadcast(message, sender_socket):
    """ Invia un messaggio a tutti i client tranne chi lo ha inviato """
    for client, username in connected_clients.items():
        if client != sender_socket:
            try:
                client.send(message.encode())
            except:
                client.close()
                del connected_clients[client]

def handle_client(client_socket, addr):
    global server_running
    print(f"{GREEN}✅ Connessione accettata da {addr}{RESET}")

    try:
        action = client_socket.recv(1024).decode().strip()
        encrypted_creds = client_socket.recv(4096)
        credentials = decrypt_data(encrypted_creds)
        username, password = credentials.split("|")

        users = load_users()
        hashed_password = hash_password(password)

        if action == "register":
            if username in users:
                client_socket.send("❌ Errore: Username già registrato!".encode())
                client_socket.close()
                return
            users[username] = {"password": hashed_password, "role": "user"}
            if username == "admin":
                users[username]["role"] = "admin"
            save_users(users)
            client_socket.send("✅ Registrazione completata! Ora puoi fare il login.".encode())

        elif action == "login":
            if username not in users or users[username]["password"] != hashed_password:
                client_socket.send("❌ Autenticazione fallita!".encode())
                client_socket.close()
                return
            role = users[username]["role"]
            client_socket.send(f"✅ Autenticazione riuscita! Ruolo: {role}".encode())
            connected_clients[client_socket] = username  # Aggiunge il client alla lista

        else:
            client_socket.send("❌ Azione non valida!".encode())
            client_socket.close()
            return

        while True:
            encrypted_data = client_socket.recv(4096)
            if not encrypted_data:
                break

            data = decrypt_data(encrypted_data)

            if data.strip() == "/exit":
                print(f"🔌 {username} si è disconnesso correttamente.")
                client_socket.send("✅ Disconnessione riuscita.".encode())
                del connected_clients[client_socket]  # Rimuove il client
                client_socket.close()
                break

            if data.strip() == "/help":
                help_text = "\n📜 **Comandi disponibili:**\n"
                help_text += "────────────────────────────────\n"
                help_text += "✅ `/exit` - 🔌 Disconnettersi\n"
                if users[username]["role"] == "admin":
                    help_text += "✅ `/shutdown` - 🔴 Spegnere il server (solo admin)\n"
                    help_text += "✅ `/restart` - 🔄 Riavviare il server (solo admin)\n"
                help_text += "────────────────────────────────"
                client_socket.send(help_text.encode())
                continue

            if data.strip() == "/shutdown":
                if users[username]["role"] == "admin":
                    print(f"🛑 {username} (ADMIN) ha spento il server!")
                    client_socket.send("🛑 Il server si sta spegnendo...".encode())
                    server_running = False
                    client_socket.close()
                    break
                else:
                    client_socket.send("❌ Permesso negato! Solo un admin può spegnere il server.".encode())

            if data.strip() == "/restart":
                if users[username]["role"] == "admin":
                    print(f"🔄 {username} (ADMIN) ha riavviato il server!")
                    client_socket.send("🔄 Il server si sta riavviando...".encode())
                    os.execv(__file__, ["python"] + sys.argv)
                else:
                    client_socket.send("❌ Permesso negato! Solo un admin può riavviare il server.".encode())

            print(f"{CYAN}📥 Ricevuto da {username}: {data}{RESET}")

            # Invia il messaggio a tutti i client
            broadcast(f"📩 [{username}]: {data}", client_socket)

    except Exception as e:
        print(f"{RED}❌ Errore: {e}{RESET}")
    finally:
        if client_socket in connected_clients:
            del connected_clients[client_socket]
        client_socket.close()

if __name__ == "__main__":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 8080))
    server.listen(10)  # Supporta fino a 10 connessioni simultanee
    print(f"{GREEN}🟢 Server VPN in ascolto su 0.0.0.0:8080{RESET}")

    while server_running:
        client_socket, addr = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_handler.start()
