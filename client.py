import socket
from Crypto.Cipher import AES

SECRET_KEY = b"0123456789abcdef"

def encrypt_data(data):
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX)
    return cipher.nonce + cipher.encrypt(data.encode())

def connect_to_vpn(server_ip="127.0.0.1", server_port=8080):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((server_ip, server_port))
    print(f"🟢 Connesso a {server_ip}:{server_port}")

    action = input("Vuoi registrarti o loggarti? (register/login): ").strip().lower()
    client.send(action.encode())

    username = input("Username: ")
    password = input("Password: ")

    credentials = f"{username}|{password}"
    encrypted_credentials = encrypt_data(credentials)

    client.send(encrypted_credentials)
    auth_response = client.recv(1024).decode()

    if "Autenticazione fallita" in auth_response or "Errore" in auth_response:
        print(f"❌ {auth_response}")
        client.close()
        return

    print(f"✅ {auth_response}")

    while True:
        message = input("💬 Scrivi un messaggio (oppure /help per i comandi disponibili): ")

        if message.strip().lower() == "/exit":
            client.send(encrypt_data("/exit"))
            response = client.recv(1024).decode()
            print(f"🔌 {response}")
            client.close()
            break

        if message.strip().lower() == "/help":
            client.send(encrypt_data("/help"))
            response = client.recv(1024).decode()
            print(response)
            continue

        if message.strip().lower() in ["/shutdown", "/restart"]:
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
        print(f"📩 Risposta del server: {response.decode()}")

if __name__ == "__main__":
    connect_to_vpn()
