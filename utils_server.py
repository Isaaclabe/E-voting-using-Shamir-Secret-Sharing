import struct
import pickle

CHUNK_SIZE = 16384  # Size of each data chunk to send or receive

def send_large_data(sock, data):
    """
    Sends large data over a socket connection by breaking it into smaller chunks.

    Args:
        sock (socket): The socket object to send data through.
        data: The data to be sent. Can be any serializable Python object.
    """
    # Serialize the data to a byte stream
    data_serialized = pickle.dumps(data)
    data_size = len(data_serialized)

    # Send the size of the serialized data
    sock.sendall(struct.pack('>I', data_size))
    
    # Send the data in chunks
    for i in range(0, data_size, CHUNK_SIZE):
        chunk = data_serialized[i:i + CHUNK_SIZE]
        sock.sendall(chunk)

def receive_large_data(sock):
    """
    Receives large data over a socket connection by reading it in smaller chunks.

    Args:
        sock (socket): The socket object to receive data from.

    Returns:
        The data received, deserialized into its original Python object form.
    """
    # Receive the size of the incoming data
    data_size = struct.unpack('>I', sock.recv(4))[0]
    chunks = []
    bytes_recd = 0

    # Receive the data in chunks until the complete data is received
    while bytes_recd < data_size:
        chunk = sock.recv(min(data_size - bytes_recd, CHUNK_SIZE))
        chunks.append(chunk)
        bytes_recd += len(chunk)
    
    # Deserialize the complete byte stream back into the original data object
    return pickle.loads(b''.join(chunks))
