import socket
import threading
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def load_config():
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
            return config.get('ip', '127.0.0.1'), config.get('port', 9595)
    except FileNotFoundError:
        print("Arquivo config.json não encontrado. Usando valores padrão.")
        return '127.0.0.1', 9595
    except json.JSONDecodeError:
        print("Erro ao ler config.json. Usando valores padrão.")
        return '127.0.0.1', 9595

def generate_dh_parameters():
    return dh.generate_parameters(generator=2, key_size=2048)

def perform_key_exchange(conn, parameters):
    server_private_key = parameters.generate_private_key()

    conn.send(parameters.parameter_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.ParameterFormat.PKCS3
    ))

    conn.send(server_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    client_public_key_bytes = conn.recv(2048)
    client_public_key = serialization.load_der_public_key(client_public_key_bytes)

    shared_key = server_private_key.exchange(client_public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

    return derived_key

def handle_client(client_socket, address):
    print(f"[NOVA CONEXÃO] {address} conectado.")
    try:
        parameters = generate_dh_parameters()
        aes_key = perform_key_exchange(client_socket, parameters)
        cipher = Fernet(base64.urlsafe_b64encode(aes_key))

        client_socket.send(cipher.encrypt(b"Handshake completo. Conexao segura estabelecida."))

        while True:
            encrypted_msg = client_socket.recv(2048)
            if not encrypted_msg:
                break

            print(f"[CRIPTOGRAFADO de {address}] {encrypted_msg}")
            msg = cipher.decrypt(encrypted_msg).decode()
            print(f"[{address}] {msg}")

            response = f"Servidor recebeu: {msg}"
            client_socket.send(cipher.encrypt(response.encode()))
    except Exception as e:
        print(f"[ERRO Handshake] {e}")
    finally:
        client_socket.close()
        print(f"[DESCONECTADO] {address} desconectado.")

def main():
    ip, port = load_config()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ip, port))
    server.listen()
    print(f"[INICIADO] Servidor escutando em {ip}:{port}...")

    while True:
        client_socket, addr = server.accept()
        print(f"[CONECTADO] Cliente {addr} conectado.")
        threading.Thread(target=handle_client, args=(client_socket, addr)).start()

if __name__ == "__main__":
    main()
