import socket
import threading
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def carregar_configuracao():
    try:
        with open('clientconfig.json', 'r') as f:
            config = json.load(f)
            return config.get('ip', '127.0.0.1'), config.get('port', 9595)
    except FileNotFoundError:
        print("[AVISO] Arquivo clientconfig.json não encontrado. Usando valores padrão.")
        return '127.0.0.1', 9595
    except json.JSONDecodeError:
        print("[AVISO] Erro ao ler clientconfig.json. Usando valores padrão.")
        return '127.0.0.1', 9595

def perform_key_exchange(sock):
    parameters_bytes = sock.recv(2048)
    parameters = serialization.load_der_parameters(parameters_bytes)

    server_public_key_bytes = sock.recv(2048)
    server_public_key = serialization.load_der_public_key(server_public_key_bytes)

    client_private_key = parameters.generate_private_key()

    sock.send(client_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    shared_key = client_private_key.exchange(server_public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

    return derived_key

def receber_mensagens(sock, cipher):
    while True:
        try:
            encrypted_msg = sock.recv(2048)
            if not encrypted_msg:
                print("[INFO] Conexão encerrada pelo servidor.")
                break
            mensagem = cipher.decrypt(encrypted_msg).decode()
            print(f"[CRIPTOGRAFADO de SERVIDOR] {encrypted_msg}")
            print(f"[SERVIDOR]: {mensagem}")
        except Exception as e:
            print(f"[ERRO] Falha ao receber mensagem: {e}")
            break

def main():
    ip, porta = carregar_configuracao()
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        cliente.connect((ip, porta))
        print(f"[SUCESSO] Conectado ao servidor em {ip}:{porta}.")

        aes_key = perform_key_exchange(cliente)
        cipher = Fernet(base64.urlsafe_b64encode(aes_key))

        handshake_msg = cipher.decrypt(cliente.recv(2048)).decode()
        print(f"[HANDSHAKE] {handshake_msg}")

        thread = threading.Thread(target=receber_mensagens, args=(cliente, cipher))
        thread.daemon = True
        thread.start()

        while True:
            msg = input()
            if msg.lower() == 'sair':
                print("[INFO] Encerrando conexão com o servidor.")
                break
            encrypted_msg = cipher.encrypt(msg.encode())
            cliente.send(encrypted_msg)
    except Exception as e:
        print(f"[FALHA] Não foi possível estabelecer conexão segura. Erro: {e}")
    finally:
        cliente.close()

if __name__ == "__main__":
    main()
