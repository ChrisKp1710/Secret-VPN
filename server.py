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
connected_clients = {}  # Dizionario {client_socket: username}

def load_users():
    """ Carica gli utenti dal file """
    if not os.path.exists(USER_DB_FILE):
        return {}
    with open(USER_DB_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    """ Salva gli utenti nel file """
    with open(USER_DB_FILE, "w") as f:
        json.dump(users, f, indent=4)

def hash_password(password):
    """ Hash della password con SHA256 """
    return hashlib.sha256(password.encode()).hexdigest()

def decrypt_data(data):
    """ Decifra i dati ricevuti """
    nonce = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode()

def broadcast(message, sender_socket=None):
    """ Invia un messaggio a tutti gli utenti connessi """
    to_remove = []
    for client, username in connected_clients.items():
        if client != sender_socket:
            try:
                client.send(message.encode())
            except:
                client.close()
                to_remove.append(client)

    for client in to_remove:
        del connected_clients[client]

def handle_client(client_socket, addr):
    """ Gestisce un client connesso """
    global server_running
    print(f"✅ Connessione accettata da {addr[0]}:{addr[1]}")

    try:
        action = client_socket.recv(1024).decode().strip()
        encrypted_creds = client_socket.recv(4096)
        credentials = decrypt_data(encrypted_creds)
        username, password = credentials.split("|")

        users = load_users()
        hashed_password = hash_password(password)

        if action == "register":
            if username in users:
                client_socket.send("❌ Username già registrato!".encode())
                client_socket.close()
                return

            # Il primo utente registrato è admin, gli altri sono user
            role = "admin" if not users else "user"
            users[username] = {"password": hashed_password, "role": role}
            save_users(users)
            client_socket.send(f"✅ Registrazione completata! Sei stato registrato come {role}.".encode())

        elif action == "login":
            if username not in users or users[username]["password"] != hashed_password:
                client_socket.send("❌ Autenticazione fallita!".encode())
                client_socket.close()
                return

            role = users[username]["role"]
            client_socket.send(f"✅ Autenticazione riuscita! Ruolo: {role}".encode())

        connected_clients[client_socket] = username  # Aggiungi il client
        print(f"🟢 {username} ({addr[0]}:{addr[1]}) si è connesso.")
        broadcast(f"🔵 {username} si è unito alla chat.")

        while True:
            encrypted_data = client_socket.recv(4096)
            if not encrypted_data:
                break

            data = decrypt_data(encrypted_data).strip()

            if data == "/exit":
                print(f"🔴 {username} si è disconnesso.")
                client_socket.send("✅ Disconnessione riuscita.".encode())
                del connected_clients[client_socket]
                client_socket.close()
                broadcast(f"🔴 {username} ha lasciato la chat.")
                break

            if data == "/help":
                help_text = "\n📜 **Comandi disponibili:**\n"
                help_text += "────────────────────────────────\n"
                help_text += "✅ `/exit` - 🔌 Disconnettersi\n"
                help_text += "✅ `/help` - ℹ️ Mostra i comandi disponibili\n"
                help_text += "✅ `/clear` - 🧹 Pulisce lo schermo\n"
                if users[username]["role"] == "admin":
                    help_text += "✅ `/shutdown` - 🔴 Spegnere il server (solo admin)\n"
                    help_text += "✅ `/restart` - 🔄 Riavviare il server (solo admin)\n"
                    help_text += "✅ `/list_users` - 📋 Mostra tutti gli utenti registrati\n"
                    help_text += "✅ `/promote [username]` - 🏅 Promuovere un utente a admin\n"
                    help_text += "✅ `/demote [username]` - 🔻 Retrocedere un admin a user\n"
                help_text += "────────────────────────────────"
                client_socket.send(help_text.encode())
                continue

            if data == "/list_users":
                if users[username]["role"] != "admin":
                    client_socket.send("❌ Permesso negato! Solo un admin può usare questo comando.".encode())
                    continue
                user_list = "\n👥 **Utenti registrati:**\n"
                user_list += "\n".join([f"- {user} ({info['role']})" for user, info in users.items()])
                client_socket.send(user_list.encode())
                continue

            if data.startswith("/promote "):
                if users[username]["role"] != "admin":
                    client_socket.send("❌ Permesso negato! Solo un admin può usare questo comando.".encode())
                    continue

                _, target_user = data.split(" ", 1)

                if target_user not in users:
                    client_socket.send("❌ Utente non trovato.".encode())
                elif users[target_user]["role"] == "admin":
                    client_socket.send("❌ L'utente è già un admin.".encode())
                else:
                    users[target_user]["role"] = "admin"
                    save_users(users)
                    client_socket.send(f"🏅 {target_user} è stato promosso ad admin!".encode())
                    broadcast(f"🎉 {target_user} è stato promosso ad admin!", sender_socket=client_socket)

                continue

            if data.startswith("/demote "):
                if users[username]["role"] != "admin":
                    client_socket.send("❌ Permesso negato! Solo un admin può usare questo comando.".encode())
                    continue

                _, target_user = data.split(" ", 1)

                if target_user not in users:
                    client_socket.send("❌ Utente non trovato.".encode())
                elif users[target_user]["role"] == "user":
                    client_socket.send("❌ L'utente è già un user.".encode())
                else:
                    users[target_user]["role"] = "user"
                    save_users(users)
                    client_socket.send(f"🔻 {target_user} è stato retrocesso a user!".encode())
                    broadcast(f"🔻 {target_user} è stato retrocesso a user!", sender_socket=client_socket)

                continue

            if data == "/shutdown":
                if users[username]["role"] != "admin":
                    client_socket.send("❌ Permesso negato! Solo un admin può spegnere il server.".encode())
                    continue
                client_socket.send("🛑 Il server si sta spegnendo...".encode())
                print("🛑 Server in fase di spegnimento...")
                os._exit(0)

            broadcast(f"📩 [{username}]: {data}", sender_socket=client_socket)

    except Exception as e:
        print(f"❌ Errore con {username}: {e}")
    finally:
        if client_socket in connected_clients:
            del connected_clients[client_socket]
        client_socket.close()

if __name__ == "__main__":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 8080))
    server.listen(10)  
    print("🟢 Server VPN in ascolto su 0.0.0.0:8080")

    while server_running:
        client_socket, addr = server.accept()
        threading.Thread(target=handle_client, args=(client_socket, addr), daemon=True).start()
