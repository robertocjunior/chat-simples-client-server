import socket
import threading
import json

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

def receber_mensagens(sock):
    while True:
        try:
            mensagem = sock.recv(1024).decode()
            if not mensagem:
                print("[INFO] Conexão encerrada pelo servidor.")
                break
            print(f"[SERVIDOR]: {mensagem}")
        except:
            print("[ERRO] Falha ao receber mensagem.")
            break

def main():
    ip, porta = carregar_configuracao()
    
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        cliente.connect((ip, porta))
        print(f"[SUCESSO] Conectado ao servidor em {ip}:{porta}.")
    except Exception as e:
        print(f"[FALHA] Não foi possível conectar ao servidor em {ip}:{porta}. Erro: {e}")
        return

    thread = threading.Thread(target=receber_mensagens, args=(cliente,))
    thread.daemon = True  # Permite que o programa termine mesmo com a thread ativa
    thread.start()

    try:
        while True:
            msg = input()
            if msg.lower() == 'sair':
                print("[INFO] Encerrando conexão com o servidor.")
                break
            cliente.send(msg.encode())
    except KeyboardInterrupt:
        print("\n[INFO] Conexão interrompida pelo usuário.")
    finally:
        cliente.close()

if __name__ == "__main__":
    main()