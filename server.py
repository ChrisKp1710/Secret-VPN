import socket
import sys
import threading
import hashlib
import json
import os
from Crypto.Cipher import AES

USER_DB_FILE = "users.db"
SECRET_KEY = b"0123456789abcdef"
server_running = True  # Variabile globale per il controllo del server

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
    global server_running
    print(f"✅ Connessione accettata da {addr}")

    try:
        action = client_socket.recv(1024).decode().strip()
        encrypted_creds = client_socket.recv(4096)
        credentials = decrypt_data(encrypted_creds)
        username, password = credentials.split("|")

        users = load_users()
        hashed_password = hash_password(password)

        if action == "register":
            if username in users:
                client_socket.send("❌ Errore: Username già registrato!".encode("utf-8"))
                client_socket.close()
                return
            users[username] = {"password": hashed_password, "role": "user"}
            if username == "admin":
                users[username]["role"] = "admin"
            save_users(users)
            client_socket.send("✅ Registrazione completata! Ora puoi fare il login.".encode("utf-8"))

        elif action == "login":
            if username not in users or users[username]["password"] != hashed_password:
                client_socket.send("❌ Autenticazione fallita!".encode("utf-8"))
                client_socket.close()
                return
            role = users[username]["role"]
            client_socket.send(f"✅ Autenticazione riuscita! Ruolo: {role}".encode("utf-8"))

        else:
            client_socket.send("❌ Azione non valida!".encode("utf-8"))
            client_socket.close()
            return

        while True:
            encrypted_data = client_socket.recv(4096)
            if not encrypted_data:
                break

            data = decrypt_data(encrypted_data)

            if data.strip() == "/exit":
                print(f"🔌 {username} si è disconnesso correttamente.")
                client_socket.send("✅ Disconnessione riuscita.".encode("utf-8"))
                client_socket.close()
                break

            if data.strip() == "/help":
                help_text = "\n📜 **Comandi disponibili:**\n"
                help_text += "────────────────────────────────\n"
                help_text += "✅ `/exit` - 🔌 Disconnettersi\n"
                if users[username]["role"] == "admin":
                    help_text += "✅ `/shutdown` - 🛑 Spegnere il server\n"
                    help_text += "✅ `/restart` - 🔄 Riavviare il server\n"
                help_text += "────────────────────────────────"
                client_socket.send(help_text.encode("utf-8"))
                continue

            if data.strip() == "/shutdown":
                if users[username]["role"] == "admin":
                    print(f"🛑 {username} (ADMIN) ha spento il server!")
                    client_socket.send("🛑 Il server si sta spegnendo...".encode("utf-8"))
                    server_running = False
                    client_socket.close()
                    break
                else:
                    client_socket.send("❌ Permesso negato! Solo un admin può spegnere il server.".encode("utf-8"))

            if data.strip() == "/restart":
                if users[username]["role"] == "admin":
                    print(f"🔄 {username} (ADMIN) ha riavviato il server!")
                    client_socket.send("🔄 Il server si sta riavviando...".encode("utf-8"))
                    os.execv(__file__, ["python"] + sys.argv)
                else:
                    client_socket.send("❌ Permesso negato! Solo un admin può riavviare il server.".encode("utf-8"))

            print(f"📩 Ricevuto da {username} ({addr}): {data}")
            client_socket.send("📩 Messaggio ricevuto dal server".encode("utf-8"))
    except Exception as e:
        print(f"⚠️ Errore con {addr}: {e}")

    client_socket.close()

def start_vpn_server(host="0.0.0.0", port=8080):
    global server_running
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"🟢 Server VPN in ascolto su {host}:{port}")

    while server_running:
        try:
            server.settimeout(1)
            client_socket, addr = server.accept()
            client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
            client_handler.start()
        except socket.timeout:
            continue

    print("🔻 Server VPN spento correttamente.")
    server.close()

if __name__ == "__main__":
    start_vpn_server()
