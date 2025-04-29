import socket
import threading
import json

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

def handle_client(client_socket, address):
    print(f"[NOVA CONEXÃO] {address} conectado.")
    client_socket.send("Conexão com o servidor estabelecida com sucesso.".encode())

    while True:
        try:
            msg = client_socket.recv(1024).decode()
            if not msg:
                break
            print(f"[{address}] {msg}")
            client_socket.send(f"Servidor recebeu: {msg}".encode())
        except:
            break

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
        thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        thread.start()

if __name__ == "__main__":
    main()