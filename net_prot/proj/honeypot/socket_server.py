import socket
import threading

def start_echo_server(host='192.168.1.1', port=12345):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"Echo server is listening on {host}:{port}")

        while True:
            client_socket, client_address = server_socket.accept()
            threading.Thread(target=handle_client, args=(client_socket, client_address, host)).start()

def handle_client(client_socket, client_address, host):
    with client_socket:
        print(f"Connected by {client_address}")
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                data = f"From server {host} ".encode() + data
                client_socket.sendall(data)
        except BrokenPipeError:
            print(f"Connection with {client_address} broken.")
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Run app1 on localhost (169.254.4.2) and port web_server_port
    t1 = threading.Thread(target=start_echo_server, args=('192.168.1.1', 5001))
    t1.start()

    # Run app2 on the dummy interface (10.133.73.14) and port web_server_port
    t2 = threading.Thread(target=start_echo_server, args=('169.254.4.2', 5001))
    t2.start()

    # Run app2 on the dummy interface (10.133.73.14) and port web_server_port
    t3 = threading.Thread(target=start_echo_server, args=('10.133.73.14', 5001))
    t3.start()

    t1.join()
    t2.join()
    t3.join()
