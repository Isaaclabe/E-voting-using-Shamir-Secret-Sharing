import socket
import threading
import pickle

from utils_server import send_large_data, receive_large_data

class ExternalServer:
    """
    The ExternalServer class represents an external server in the election system.
    It handles storing, retrieving, and deleting data based on commands received from clients.
    """
    
    def __init__(self, ip, port, buffer_size):
        """
        Initializes the ExternalServer with the given IP address, port, and buffer size.

        Args:
            ip (str): The IP address of the server.
            port (int): The port number on which the server listens.
            buffer_size (int): The buffer size for receiving data.
        """
        self.ip = ip
        self.port = port
        self.data_store = [] 
        self.buffer_size = buffer_size

    def handle_client(self, conn, addr):
        """
        Handles incoming client connections and processes their requests.

        Args:
            conn (socket): The socket connection to the client.
            addr (tuple): The address of the client.
        """
        request = receive_large_data(conn)

        if request['command'] == 'STORE_DATA':
            # Store data received from the client
            self.data_store.append(request['data'])
            response = f"Data stored at {self.ip}:{self.port}"
        
        elif request['command'] == 'RETRIEVE_DATA':
            # Retrieve all stored data
            response = self.data_store

        elif request['command'] == 'DELETE_DATA':
            # Delete specific data if it exists in the store
            if request['data'] in self.data_store:
                self.data_store.remove(request['data'])
                response = f"Data deleted from {self.ip}:{self.port}"
            else:
                response = "Data not found in the store."
        else:
            response = "Invalid command."

        # Send response back to the client
        send_large_data(conn, response)
        conn.close()
        
    def start_server(self):
        """
        Starts the external server to listen for incoming client connections and handle their requests.
        """
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.ip, self.port))
        server.listen(5)
        print(f"   External Server {self.ip}:{self.port} is running...")
        
        # Continuously accept and handle client connections
        while True:
            conn, addr = server.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            client_thread.start()
