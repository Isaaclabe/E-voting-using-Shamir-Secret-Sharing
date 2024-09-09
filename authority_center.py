import socket
import threading
import pickle
import json
import requests
import time
import os

import math
import random
import struct
import argparse
from sympy import nextprime, mod_inverse
from datetime import datetime, timedelta
from tabulate import tabulate

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from phe import paillier

from external_server import ExternalServer
from voters import Voter
from utils_server import send_large_data, receive_large_data


class AuthorityCenter:
    def __init__(self, num_voters, num_candidates, num_bits, num_shares, threshold, tolerance, prime, buffer_size):
        self.num_voters = num_voters
        self.num_candidates = num_candidates
        self.num_bits_per_vote = num_bits
        self.num_shares = num_shares
        self.threshold = threshold
        self.tolerance = tolerance
        self.total_vote_bits = num_bits * num_candidates
        self.prime = prime
        self.buffer_size = buffer_size

        self.ip_address = '127.0.0.1'
        self.num_external_servers = num_shares
        self.external_server_ports = []
        
        self.candidate_results = [0] * num_candidates
        self.participation = 0
        self.result_table = {}
        self.is_close = False

        # Initialize Voters
        self.voter_registry = [Voter() for _ in range(self.num_voters)]
        self.voter_ids = self.initialize_voters()
        self.voter_public_keys, self.voter_private_keys = {}, {}
        
        # Generate Authority Center's Public and Private Keys
        self.authority_center_private_key, self.AC_public_key = self.generate_ECC_keys()
        
        # Set public keys for signing and voting terminal
        self.VT_signing_public_key = None
        self.VT_public_key = None
        self.homomorphic_public_key = None


    ###########################################
    ###### Voter Initialization Process #######
    ###########################################
        
    def initialize_voters(self):
        """
        Initializes the list of voter IDs from the voter registry.
        
        Returns:
            list: A list of voter IDs extracted from the voter registry.
        """
        voter_ids = []
        for voter in self.voter_registry:
            voter_ids.append(voter.id)
        return voter_ids


    #################################
    ###### Getter Functions #########
    #################################

    def get_external_server_ports(self):
        """
        Retrieves the list of external server ports that are used for communication.

        Returns:
            list: A list of external server ports.
        """
        return [port for port in self.external_server_ports]
        
    def get_authority_center_public_key(self):
        """
        Returns the public key of the Authority Center.

        Returns:
            ECC.EccKey: The Authority Center's public key.
        """
        return self.AC_public_key
        
    def get_voter_public_keys(self):
        """
        Returns the public keys of all registered voters.

        Returns:
            list: A list of ECC public keys for all registered voters.
        """
        return self.voter_public_keys
        
    def get_voter_ids(self):
        """
        Returns the list of voter IDs.

        Returns:
            list: A list of voter IDs.
        """
        return self.voter_ids
        

    ###########################
    ###### Key Functions ######
    ###########################
    
    def generate_ECC_keys(self):
        """
        Generates a pair of ECC keys.

        Returns:
            tuple: A tuple containing the ECC private key and public key.
        """
        private_key = ECC.generate(curve='P-256')
        public_key = private_key.public_key()
        return private_key, public_key

    def reconstruct_homomorphic_public_key(self, public_key_n):
        """
        Reconstructs a homomorphic public key from the provided modulus 'n'.

        Args:
            public_key_n (int): The modulus 'n' of the Paillier public key.
        
        Returns:
            paillier.PaillierPublicKey: The reconstructed Paillier public key.
        """
        return paillier.PaillierPublicKey(public_key_n)
        
    def reconstruct_ECC_key(self, curve, point_x, point_y):
        """
        Reconstructs an ECC public key using the curve type and point coordinates (x, y).

        Args:
            curve (str): The name of the elliptic curve (e.g., 'P-256').
            point_x (int): The x-coordinate of the ECC point.
            point_y (int): The y-coordinate of the ECC point.

        Returns:
            ECC.EccKey: The reconstructed ECC public key.
        """
        return ECC.construct(curve=curve, point_x=point_x, point_y=point_y)


    #############################
    ###### Utils Functions ######
    #############################
    
    def string_to_int(self, s: str) -> int:
        """
        Converts a string to an integer by encoding the string into bytes and then interpreting
        those bytes as a large integer.

        Args:
            s (str): The input string to be converted.

        Returns:
            int: The integer representation of the string.
        """
        return int.from_bytes(s.encode('utf-8'), 'big')
        
    def bytes_to_tuple(self, byte_data, length=2):
        """
        Converts byte data back into a tuple of integers.

        Args:
            byte_data (bytes): The byte data to convert.
            length (int): The number of elements in the tuple. Default is 2.

        Returns:
            tuple: A tuple of integers unpacked from the byte data.
        """
        format_string = 'q' * length
        return struct.unpack(format_string, byte_data)
        
    def bytes_to_int(self, byte_data):
        """
        Converts byte data back into an integer.

        Args:
            byte_data (bytes): The byte data to convert.

        Returns:
            int: The integer unpacked from the byte data.
        """
        return struct.unpack('q', byte_data)[0]
        
    def election_closer(self):
        """
        Marks the election as closed by setting the 'is_close' flag to True.
        """
        self.is_close = True
        

    ######################################
    ###### External Server Process #######
    ######################################

    def start_external_servers(self):
        """
        Starts the specified number of external servers for handling vote shares or other election-related data.
        """
        for i in range(self.num_external_servers):
            ip = self.ip_address
            port = 9000 + i
            external_server = ExternalServer(ip, port, self.buffer_size)
            server_thread = threading.Thread(target=external_server.start_server)
            server_thread.start()
            self.external_server_ports.append(port)
            time.sleep(0.01)

    def retrieve_data_from_external_servers(self, server_ports):
        """
        Retrieves data from the external servers by sending a 'RETRIEVE_DATA' command to each specified port.

        Args:
            server_ports (list): A list of external server ports to retrieve data from.

        Returns:
            dict: A dictionary where each key is a server port and the value is the data retrieved from that server.
        """
        all_data = {}
        for port in server_ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((self.ip_address, port))
                
                request = {'command': 'RETRIEVE_DATA'}
                
                send_large_data(sock, request)
                response = receive_large_data(sock)
                all_data[port] = response
        return all_data
        
    def delete_data_from_external_servers(self, server_ports):
        """
        Sends a 'DELETE_DATA' command to the external servers to delete the data stored on them.
        
        Args:
            server_ports (list): A list of external server ports where data will be deleted.
        """
        for port in server_ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((self.ip_address, port))
                
                request = {'command': 'DELETE_DATA'}
                
                sock.sendall(pickle.dumps(request))


    ##########################################
    ###### Server Communication Process ######
    ##########################################
    
    def start_authority_center(self):
        """
        Starts the Authority Center server to handle incoming connections from Voting Terminals.
        """
        authority_center_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        authority_center_socket.bind((self.ip_address, 8000))
        authority_center_socket.listen(5)
        
        while True:
            conn, addr = authority_center_socket.accept()
            client_thread = threading.Thread(target=self.handle_voting_terminal, args=(conn, addr))
            client_thread.start()

    def handle_voting_terminal(self, conn, addr):
        """
        Handles requests from the Voting Terminal.

        Args:
            conn: The socket connection to the Voting Terminal.
            addr: The address of the connected Voting Terminal.
        """
        try:
            request = receive_large_data(conn)
            
            if request['command'] == 'AC_SEND_PUBLIC_INFO':
                transformed_voter_public_keys = {
                    key: {'curve': str(value.curve), 'point_x': int(value.pointQ.x), 'point_y': int(value.pointQ.y)}
                    for key, value in self.voter_public_keys.items()
                }
                response = {
                    'voters_id': self.voter_ids,
                    'external_server_ports': self.external_server_ports,
                    'AC_public_key': {
                        'curve': str(self.AC_public_key.curve),
                        'point_x': int(self.AC_public_key.pointQ.x),
                        'point_y': int(self.AC_public_key.pointQ.y)
                    }
                }
                
            elif request['command'] == 'AC_SEND_ENCRYPTED_IDS':
                encrypted_server_ids = [self.homomorphic_public_key.encrypt(self.string_to_int(id)) for id in self.voter_ids]
                encrypted_server_values = [(encrypted.ciphertext(), encrypted.exponent) for i, encrypted in enumerate(encrypted_server_ids)]
                response = {
                    'encrypted_voters_id': encrypted_server_values,
                    'is_close': self.is_close,
                }
            
            elif request['command'] == 'VT_SEND_PUBLIC_KEYS':
                info = request['data']
                response = {"status": "received", "info": info}
                self.signing_public_key = self.reconstruct_ECC_key(info['signing_public_key']['curve'], info['signing_public_key']['point_x'], info['signing_public_key']['point_y'])
                self.VT_public_key = self.reconstruct_ECC_key(info['VT_public_key']['curve'], info['VT_public_key']['point_x'], info['VT_public_key']['point_y'])
                print(f"\033[0;35mReceived the VT signing public key from the Voting Terminal!\033[0m\n")
                print(f"\033[0;35mReceived the voting terminal public key from the Voting Terminal!\033[0m\n")
            
            
            elif request['command'] == 'VT_SEND_HOMOMORPHIC_PUBLIC_KEY':
                info = request['data']
                response = {"status": "received", "info": info}
                self.homomorphic_public_key = self.reconstruct_homomorphic_public_key(info)
            
            
            elif request['command'] == 'AC_SEND_VOTER_PUBLIC_KEY':
                new_id = request['data']
                private_key_voter, public_key_voter = self.generate_ECC_keys()
                self.voter_public_keys[new_id] = public_key_voter
                self.voter_private_keys[new_id] = private_key_voter
                response = {
                    'public_key': {
                        'curve': str(public_key_voter.curve),
                        'point_x': int(public_key_voter.pointQ.x),
                        'point_y': int(public_key_voter.pointQ.y)
                    }
                }
            send_large_data(conn, response)
        except Exception as e:
            print(f"Error in handle_voting_terminal: {e}")
        finally:
            conn.close()
            
            
    ####################################
    ###### Verification Functions ######
    ####################################
    
    def verify_signature(self, signing_public_key, data, signature):
        """
        Verifies the digital signature of a given data item using the provided signing public key.

        Args:
            signing_public_key (ECC.EccKey): The public key used to verify the signature.
            data (bytes): The data that was signed.
            signature (bytes): The digital signature to verify.
        
        Returns:
            bool: True if the signature is valid, False if the verification fails.
        """
        hash_obj = SHA256.new(data)
        verifier = DSS.new(signing_public_key, 'fips-186-3')
        try:
            verifier.verify(hash_obj, signature)
            return True
        except ValueError:
            print("Signature verification failed.")
            return False
            
            
    ##################################
    ###### Decryption Functions ######
    ##################################

    def decrypt_vote(self, VT_public_key, voter_private_key, encrypted_data, iv):
        """
        Decrypts an encrypted vote using ECDH key exchange and AES in CBC mode.

        Args:
            VT_public_key (ECC.EccKey): The public key of the Voting Terminal.
            voter_private_key (ECC.EccKey): The private key of the voter used for decryption.
            encrypted_data (bytes): The encrypted vote data to be decrypted.
            iv (bytes): The initialization vector (IV) used for AES encryption.

        Returns:
            bytes: The decrypted vote data.
        """
        shared_secret_point = VT_public_key.pointQ * voter_private_key.d
        shared_secret_bytes = int(shared_secret_point.x).to_bytes(32, byteorder='big')
        aes_key = SHA256.new(shared_secret_bytes).digest()
        
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted_data), AES.block_size)


    ##############################
    ###### Decode Functions ######
    ##############################
    
    def decode_vote_result(self, reconstructed_secret, total_bits, num_candidates):
        """
        Decodes the reconstructed secret into individual vote counts for each candidate.
        
        Args:
            reconstructed_secret (int): The secret representing the encoded votes.
            total_bits (int): The total number of bits used to represent the votes.
            num_candidates (int): The total number of candidates.

        Returns:
            list: A list containing the vote counts for each candidate.
        """
        binary_string = format(reconstructed_secret, f'0{total_bits}b')
        bits_per_candidate = total_bits // num_candidates
        candidate_vote_counts = [
            int(binary_string[i:i+bits_per_candidate], 2)
            for i in range(0, total_bits, bits_per_candidate)
        ]
    
        return candidate_vote_counts


    ###########################################
    ###### Shamir Secret Sharing Process ######
    ###########################################
      
    def reconstruct_secret(self, shares, prime):
        """
        Reconstructs a secret from the provided shares using Shamir's Secret Sharing scheme.

        Args:
            shares (list): A list of shares, where each share is a tuple (x, y).
            prime (int): A prime number used for modular arithmetic.

        Returns:
            int: The reconstructed secret.
        """
        total_sum = 0
        k = len(shares)
        for i in range(k):
            x_i, y_i = shares[i]
            product = y_i
            for j in range(k):
                if i != j:
                    x_j, _ = shares[j]
                    product *= x_j * mod_inverse(x_j - x_i, prime) % prime
                    product %= prime
            total_sum += product
            total_sum %= prime
        return total_sum
            
            
    #################################
    ##### Main Result Process #######
    #################################
    
    def process_election_results(self):
        """
        Processes the election results by retrieving and verifying shares, detecting corrupted votes,
        reconstructing valid votes, and decoding the final results.

        The method performs the following steps:
        1. Retrieves vote shares from external servers.
        2. Verifies the signatures of the retrieved shares.
        3. Detects any corrupted shares by checking the signature verifications.
        4. If too many corrupted voters are found, it declares the election corrupted.
        5. If the election is valid, it decrypts the shares and reconstructs the votes.
        6. Decodes the final vote count for each candidate.
        
        Returns:
            bool: True if the election results were successfully processed, False otherwise.
        """
        try:
            # Retrieve shares from external servers
            all_shares = self.retrieve_data_from_external_servers(self.external_server_ports)
            
            # Verify signatures on the shares
            is_signed = {}
            for port, data in all_shares.items():
                for element in data:
                    verification_result = self.verify_signature(self.signing_public_key, element[2], element[4])
                    decrypted_random_id = self.bytes_to_int(
                        self.decrypt_vote(self.VT_public_key, self.authority_center_private_key, element[0], element[1])
                    )
                    if decrypted_random_id in is_signed:
                        is_signed[decrypted_random_id].append(verification_result)
                    else:
                        is_signed[decrypted_random_id] = [verification_result]

            corrupted_voter_list = []
            for random_id, verification_list in is_signed.items():
                if verification_list.count(False) >= self.threshold:
                    corrupted_voter_list.append(random_id)
                        
            # Check for too many corrupted shares
            if len(corrupted_voter_list) >= self.tolerance * self.num_voters:
                print("\033[91mElection corrupted: Too many corrupted voters.\033[0m")
                return False

            # Select valid servers to reconstruct the vote
            selected_server_ports = random.sample(self.external_server_ports, self.threshold)
            shares_per_vote = self.retrieve_data_from_external_servers(selected_server_ports)
            shares_per_vote = list(shares_per_vote.values())
            shares_per_vote = [list(share_tuple) for share_tuple in zip(*shares_per_vote)]
            
            # Decrypt shares and reconstruct the vote
            decrypted_shares = []
            voter_ids_voted = []
            for share_tuple in shares_per_vote:
                temp_list = []
                for share_data in share_tuple:
                    decrypted_random_id = self.bytes_to_int(self.decrypt_vote(self.VT_public_key, self.authority_center_private_key, share_data[0], share_data[1]))
                    
                    voter_private_key = self.voter_private_keys[decrypted_random_id]
                    decrypted_share_bytes = self.decrypt_vote(self.VT_public_key, voter_private_key, share_data[2], share_data[3])
                    temp_list.append(self.bytes_to_tuple(decrypted_share_bytes))
                voter_ids_voted.append(decrypted_random_id)
                if decrypted_random_id in corrupted_voter_list:
                    decrypted_shares.append("Corrupted")
                else:
                    decrypted_shares.append(temp_list)
            
            self.participation = len(decrypted_shares)
            for i, share_tuple in enumerate(decrypted_shares):
                if share_tuple == "Corrupted":
                    self.result_table[voter_ids_voted[i]] = share_tuple
                else:
                    reconstructed_vote = self.reconstruct_secret(share_tuple, self.prime)
                    decoded_vote = self.decode_vote_result(reconstructed_vote, self.total_vote_bits, self.num_candidates)
                    self.result_table[voter_ids_voted[i]] = decoded_vote
                    self.candidate_results = [
                        current + new for current, new in zip(self.candidate_results, decoded_vote)
                    ]
            return True
            
        except Exception as e:
            print(f"\033[91mAn error occurred during election result processing: {e}\033[0m")
            return False
    
    
def argmax(iterable):
    """
    Returns the index of the maximum value in the given iterable.

    Args:
        iterable (iterable): A list or other iterable object containing comparable elements.

    Returns:
        int: The index of the maximum value in the iterable.
    """
    return max(enumerate(iterable), key=lambda x: x[1])[0]
    
    
    
    
if __name__ == "__main__":
    ######################################
    #### Setup command-line argument #####
    ######################################
    
    parser = argparse.ArgumentParser(description="\033[96mElection System Parameters\033[0m")
    parser.add_argument("--num_voters", type=int, default=10, help="Number of voters (default: 10)")
    parser.add_argument("--candidates", type=str, default="Alice,Bob,Charles,David", help="Comma-separated list of candidate names (default: Alice,Bob,Charles,David)")
    parser.add_argument("--num_shares", type=int, default=10, help="Number of shares for secret sharing (default: 4)")
    parser.add_argument("--threshold", type=int, default=7, help="Threshold for secret reconstruction (default: 3)")
    parser.add_argument("--tolerance", type=float, default=0.5, help="Percentage of corrupted voter accepted before cancel the election (default: 10%)")
    parser.add_argument("--duration", type=float, default=0.5, help="Election duration in minutes (default: 1)")
    parser.add_argument("--buffer_size", type=int, default=16384*4, help="Buffer size for data transmission (default: 16384)")
    args = parser.parse_args()
    
    
    ######################################
    ######## Setup the parameters ########
    ######################################
    
    candidate_names = args.candidates.split(",")
    candidate_names.append("Blank")
    num_voters = args.num_voters
    num_candidates = len(candidate_names)
    num_bits_per_vote = math.floor(math.log2(num_voters)) + 1
    total_vote_bits = num_bits_per_vote * num_candidates
    prime_number = nextprime(2**(total_vote_bits - num_bits_per_vote) * (num_candidates + 1))
    num_shares = args.num_shares
    threshold = args.threshold
    tolerance = args.tolerance
    election_duration = timedelta(minutes=args.duration)
    buffer_size = args.buffer_size
    
    print("\033[96m============================")
    print("\033[1;36m===== Election Details =====")
    print("\033[96m============================\033[0m\n")
    print(f"Number of registered voters: {num_voters}")
    print(f"Number of candidates: {num_candidates - 1}, {candidate_names[:-1]}")
    print(f"Duration: {election_duration}\n")
    
    
    ######################################
    ##### Setup the Authority Center #####
    ######################################
    
    print(f"\033[96m=========================================")
    print(f"\033[1;36m===== Setup the Authority Center... =====")
    print(f"\033[96m=========================================\033[0m\n")
    authority_center = AuthorityCenter(num_voters, num_candidates, num_bits_per_vote, num_shares, threshold, tolerance, prime_number, buffer_size)
    print(f"\033[0;35mAuthority Center public-private key generated!\n")
    print("Start the external servers:")
    authority_center.start_external_servers()
    server_thread = threading.Thread(target=authority_center.start_authority_center)
    server_thread.start()
    
    
    ######################################
    ######### Start the election #########
    ######################################
    
    print(f"\n\033[96m==============================")
    print(f"\033[1;36m===== Start the election =====")
    print(f"\033[96m==============================\033[0m")
    election_start = datetime.now()
    election_deadline = election_start + election_duration
    print(f"\nElection opened on: {election_start.strftime('%Y-%m-%d %H:%M:%S')}, and will close at: {election_deadline.strftime('%Y-%m-%d %H:%M:%S')}\n")
    while datetime.now() < election_deadline:
        time_remaining = election_deadline - datetime.now()
        print(f"\033[93mTime remaining until election closes: {time_remaining}\033[0m", end='\r')
        time.sleep(1)
    authority_center.election_closer()
    
    
    ######################################
    ########## Tally the result ##########
    ######################################
    
    print(f"\n\033[96m===============================")
    print(f"\033[1;36m===== Tally of the result =====")
    print(f"\033[96m===============================\033[0m")
    print(f"\nElection closed. Processing results...\n")
    time.sleep(2)
    
    successful = authority_center.process_election_results()
    if successful:
        participation_rate = (authority_center.participation / num_voters * 100)
        print(f"\033[92mParticipation: {participation_rate:.2f}%\033[0m")
        table_result = [(candidate_names[i] + " ("+ str(i+1) +")", result) for i, result in enumerate(authority_center.candidate_results)]
        headers_result = ["Candidate", "Result"]
        print(f"\033[92m{tabulate(table_result, headers=headers_result, tablefmt='grid')}\033[0m")

        print(f"\nThe table of all vote:")
    table_vote = [(str(key), "\033[91mCorrupted\033[0m" if values == "Corrupted" else candidate_names[argmax(values)]) for key, values in authority_center.result_table.items()]
    headers_vote = ["Random ID", "Vote"]
    print(tabulate(table_vote, headers=headers_vote, tablefmt="grid"))
        
        
    ######################################
    ##### Clean up external servers ######
    ######################################
    
    print(f"\n\033[96m===========================")
    print(f"\033[1;36m===== Clean and close =====")
    print(f"\033[96m===========================\033[0m")
    print(f"\n\033[93mCleaning up external servers...\033[0m")
    authority_center.delete_data_from_external_servers(authority_center.get_external_server_ports())
    print(f"\nAll operations completed. Terminating program.")
    os._exit(0)



