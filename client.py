import socket
import os
from Crypto.Cipher import AES

SECRET_KEY = b"0123456789abcdef"

# Definizione colori ANSI
RESET = "\033[0m"   # Reset colore
GREEN = "\033[92m"  # Verde brillante

def encrypt_data(data):
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX)
    return cipher.nonce + cipher.encrypt(data.encode())

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

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

def connect_to_vpn(server_ip="127.0.0.1", server_port=8080):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((server_ip, server_port))
    print(f"🟢 Connesso a {server_ip}:{server_port}")

    action = input("📝 Vuoi registrarti o loggarti? (register/login): ").strip().lower()
    client.send(action.encode())

    username = input("👤 Username: ")
    password = input("🔑 Password: ")

    credentials = f"{username}|{password}"
    encrypted_credentials = encrypt_data(credentials)

    client.send(encrypted_credentials)
    auth_response = client.recv(1024).decode()

    if "Autenticazione fallita" in auth_response or "Errore" in auth_response:
        print(f"❌ {auth_response}")
        client.close()
        return

    print(f"✅ {auth_response}")

    # Estrarre il ruolo dall'autenticazione
    role = "user"
    if "Ruolo: admin" in auth_response:
        role = "admin"

    # Mostrare una sola volta l'help iniziale
    show_help(role)

    while True:
        message = input(f"💬 Scrivi un messaggio [{GREEN}{username}{RESET}]: ")

        if message.strip().lower() == "/exit":
            client.send(encrypt_data("/exit"))
            response = client.recv(1024).decode()
            print(f"🔌 {response}")
            client.close()
            break

        if message.strip().lower() == "/help":
            client.send(encrypt_data("/help"))
            response = client.recv(4096).decode()
            
            show_help(role)  # Mostra i comandi in base al ruolo
            continue  # Evita di mostrare subito l'input

        if message.strip().lower() == "/clear":
            clear_screen()
            continue  # Pulisce lo schermo e torna all'input senza inviare dati al server

        if message.strip().lower() in ["/shutdown", "/restart"]:
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
        response = client.recv(4096)
        print(f"📩 Messaggio ricevuto dal server: {response.decode()}")

if __name__ == "__main__":
    connect_to_vpn()
