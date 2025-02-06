import socket
import os
import threading
import sys
from Crypto.Cipher import AES

# Chiave segreta per la crittografia
SECRET_KEY = b"0123456789abcdef"

# Colori ANSI per evidenziare i nomi utenti (su Windows usa cmder o Windows Terminal per vederli)
COLORS = {
    "reset": "\033[0m",
    "green": "\033[92m",
    "blue": "\033[94m",
    "yellow": "\033[93m",
    "red": "\033[91m",
}

def encrypt_data(data):
    """ Crittografa i dati da inviare al server """
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX)
    return cipher.nonce + cipher.encrypt(data.encode())

def clear_screen():
    """ Pulisce lo schermo in base al sistema operativo """
    os.system('cls' if os.name == 'nt' else 'clear')

def colorize_username(username):
    """ Colora il nome utente per differenziarlo nella chat """
    return f"{COLORS['green']}[{username}]{COLORS['reset']}"

def show_help(role):
    """ Mostra i comandi disponibili in base al ruolo """
    print("\n📜 **Comandi disponibili:**")
    print("────────────────────────────────")
    print("✅ `/exit` - 🔌 Disconnettersi")
    print("✅ `/help` - ℹ️  Mostra i comandi disponibili")
    print("✅ `/clear` - 🧹 Pulisce lo schermo")
    
    if role == "admin":
        print("✅ `/shutdown` - 🔴 Spegnere il server (solo admin)")
        print("✅ `/restart` - 🔄 Riavviare il server (solo admin)")
    
    print("────────────────────────────────\n")

def receive_messages(client, username):
    """ Thread che riceve i messaggi dal server in tempo reale """
    while True:
        try:
            response = client.recv(4096).decode()
            if not response:
                break

            # Se il messaggio è di disconnessione, chiudi tutto
            if "Disconnessione riuscita." in response:
                print(f"\n✅ {response}")
                break

            # Cancella la riga corrente per evitare spostamenti brutti
            sys.stdout.write("\033[K")  
            print(f"\n💬 {response}")  

            # Ripristina il prompt solo se non è una disconnessione
            if "Connessione persa" not in response:
                print(f"💬 Scrivi un messaggio {colorize_username(username)}: ", end="", flush=True)
        except:
            print("\n❌ Connessione persa con il server.")
            break

def connect_to_vpn(server_ip="127.0.0.1", server_port=8080):
    """ Funzione principale per la connessione al server VPN """
    global username
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((server_ip, server_port))
    print(f"🟢 Connesso a {server_ip}:{server_port}")

    action = input("📝 Vuoi registrarti o loggarti? (register/login): ").strip().lower()
    client.send(action.encode())

    username = input("👤 Username: ").strip()
    password = input("🔑 Password: ").strip()

    credentials = f"{username}|{password}"
    encrypted_credentials = encrypt_data(credentials)

    client.send(encrypted_credentials)
    auth_response = client.recv(1024).decode()

    if "Autenticazione fallita" in auth_response or "Errore" in auth_response:
        print(f"❌ {auth_response}")
        client.close()
        return

    print(f"✅ {auth_response}")

    # Determinare il ruolo
    role = "user"
    if "Ruolo: admin" in auth_response:
        role = "admin"

    # Mostrare i comandi disponibili una sola volta
    show_help(role)

    # Avvia il thread per ricevere messaggi dal server
    receive_thread = threading.Thread(target=receive_messages, args=(client, username), daemon=True)
    receive_thread.start()

    while True:
        message = input(f"💬 Scrivi un messaggio {colorize_username(username)}: ").strip()

        if message.lower() == "/exit":
            client.send(encrypt_data("/exit"))
            response = client.recv(1024).decode()
            print(f"🔌 {response}")
            client.close()
            break

        if message.lower() == "/help":
            show_help(role)
            continue

        if message.lower() == "/clear":
            clear_screen()
            continue

        if message.lower() in ["/shutdown", "/restart"]:
            if role != "admin":
                print("❌ Permesso negato! Solo un admin può usare questo comando.")
                continue

            client.send(encrypt_data(message))
            response = client.recv(1024).decode()
            print(f"🛑 {response}")
            if "Il server si sta spegnendo" in response or "Il server si sta riavviando" in response:
                client.close()
                break
            continue

        encrypted_message = encrypt_data(message)
        client.send(encrypted_message)

if __name__ == "__main__":
    connect_to_vpn()
