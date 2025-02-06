import socket
from Crypto.Cipher import AES

SECRET_KEY = b"0123456789abcdef"

def encrypt_data(data):
    """Cifra i dati prima di inviarli al server"""
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX)
    return cipher.nonce + cipher.encrypt(data.encode())

def connect_to_vpn(server_ip="127.0.0.1", server_port=8080):
    """Si connette al server VPN"""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((server_ip, server_port))
    print(f"Connesso a {server_ip}:{server_port}")

    # Scelta tra registrazione o login
    action = input("Vuoi registrarti o loggarti? (register/login): ").strip().lower()
    client.send(action.encode())

    # Inserire username e password
    username = input("Username: ")
    password = input("Password: ")

    # Cifrare username e password
    credentials = f"{username}|{password}"
    encrypted_credentials = encrypt_data(credentials)

    # Invia le credenziali crittografate
    client.send(encrypted_credentials)
    auth_response = client.recv(1024).decode()

    if "Autenticazione fallita" in auth_response or "Errore" in auth_response:
        print(f"❌ {auth_response}")
        client.close()
        return

    print(f"✅ {auth_response}")

    # **Auto-login dopo la registrazione**
    if action == "register":
        print("🔄 Effettuando automaticamente il login...")
        client.send(b"login")  # Comunica al server che ora sta eseguendo il login
        client.send(encrypted_credentials)  # Reinvia le stesse credenziali per il login
        login_response = client.recv(1024).decode()

        if "Autenticazione fallita" in login_response:
            print(f"❌ {login_response}")
            client.close()
            return

        print(f"✅ {login_response}")

    # Inizio chat con il server
    while True:
        message = input("Messaggio da inviare: ")
        encrypted_message = encrypt_data(message)

        client.send(encrypted_message)
        response = client.recv(4096)
        print(f"Risposta del server: {response.decode()}")

if __name__ == "__main__":
    connect_to_vpn()
