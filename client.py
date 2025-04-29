import socket
import threading
import json
import base64
import time
import sys
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

def mostrar_animacao(event):
    """Mostra animação de carregamento enquanto o handshake está em progresso"""
    while not event.is_set():
        for i in range(4):
            if event.is_set():
                break
            sys.stdout.write('\rEstabelecendo conexão segura' + '.' * i + '   ')
            sys.stdout.flush()
            time.sleep(0.5)
    sys.stdout.write('\r' + ' ' * 50 + '\r')

def perform_key_exchange(sock, event):
    try:
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
    except Exception as e:
        print(f"\n[ERRO] Falha no handshake: {e}")
        raise
    finally:
        event.set() 

def receber_mensagens(sock, cipher):
    while True:
        try:
            encrypted_msg = sock.recv(2048)
            if not encrypted_msg:
                print("\n[INFO] Conexão encerrada pelo servidor.")
                break
                
            # Decodifica a mensagem
            mensagem = cipher.decrypt(encrypted_msg).decode()
            
            # Limpa a linha atual e mostra a mensagem formatada
            sys.stdout.write('\r' + ' ' * 100 + '\r')
            print(f"[CRIPTOGRAFADO de SERVIDOR] {encrypted_msg}")
            print(f"[SERVIDOR]: {mensagem}")
            sys.stdout.write('> ')
            sys.stdout.flush()
            
        except Exception as e:
            print(f"\n[ERRO] Falha ao receber mensagem: {e}")
            break

def main():
    ip, porta = carregar_configuracao()
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        cliente.connect((ip, porta))
        print(f"[SUCESSO] Conectado ao servidor em {ip}:{porta}.")

        # Configura animação de carregamento
        event = threading.Event()
        loading_thread = threading.Thread(target=mostrar_animacao, args=(event,))
        loading_thread.daemon = True
        loading_thread.start()

        # Realiza handshake
        aes_key = perform_key_exchange(cliente, event)
        cipher = Fernet(base64.urlsafe_b64encode(aes_key))

        handshake_msg = cipher.decrypt(cliente.recv(2048)).decode()
        print(f"\r[HANDSHAKE] {handshake_msg}")
        sys.stdout.write('> ')
        sys.stdout.flush()

        thread = threading.Thread(target=receber_mensagens, args=(cliente, cipher))
        thread.daemon = True
        thread.start()

        while True:
            sys.stdout.write('> ')
            sys.stdout.flush()
            msg = input()
            if msg.lower() == 'sair':
                print("[INFO] Encerrando conexão com o servidor.")
                break
                
            encrypted_msg = cipher.encrypt(msg.encode())
            cliente.send(encrypted_msg)

    except KeyboardInterrupt:
        print("\n[INFO] Aplicação encerrada com Ctrl+C.")
    except Exception as e:
        event.set()
        print(f"\r[FALHA] Não foi possível estabelecer conexão segura. Erro: {e}")
    finally:
        cliente.close()
        print("\n[INFO] Conexão fechada.")

if __name__ == "__main__":
    main()
