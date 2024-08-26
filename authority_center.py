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
from sympy import nextprime
from datetime import datetime, timedelta

from external_server import ExternalServer
from voters import Voter
from utils_server import send_large_data, receive_large_data
from utils_crypto import Decryptor
from utils_shamir import reconstruct_secret


class AuthorityCenter:
    """
    The AuthorityCenter class is responsible for initializing voters, managing external servers,
    handling communication with the voting terminal, and processing election results.
    """
    def __init__(self, num_voters, num_candidates, num_bits, num_shares, threshold, prime, buffer_size):
        self.num_voters = num_voters
        self.num_candidates = num_candidates
        self.num_bits_per_vote = num_bits
        self.num_shares = num_shares
        self.threshold = threshold
        self.total_vote_bits = num_bits * num_candidates
        self.prime = prime
        self.buffer_size = buffer_size
        
        self.ip_address = 'localhost'
        self.num_external_servers = num_shares
        self.external_server_ports = []
        self.candidate_results = [0] * num_candidates
        self.participation = 0
        
        # Initialize Voters
        self.voter_registry = [Voter() for _ in range(self.num_voters)]
        self.voter_ids, self.voter_public_keys, self.voter_private_keys = self.initialize_voters()
        
        # Initialize Decryptor
        self.decryptor = Decryptor()
        
        # Generate Authority Center's Public and Private Keys
        self.authority_center_private_key, self.authority_center_public_key = self.decryptor.get_authority_center_keys()
        
        # Set public keys for signing and voting terminal
        self.signing_public_key = None
        self.voting_terminal_public_key = None

    ###########################################
    ###### Voter Initialization Process #######
    ###########################################
        
    def initialize_voters(self):
        """
        Initializes voters by assigning unique IDs and generating their public and private keys.
        
        Returns:
            tuple: voter_ids, voter_public_keys, voter_private_keys
        """
        voter_public_keys = {}
        voter_private_keys = {}
        voter_ids = []
        for voter in self.voter_registry:
            voter_ids.append(voter.id)
            voter_public_keys[voter.id] = voter.public_key
            voter_private_keys[voter.id] = voter.private_key
        return voter_ids, voter_public_keys, voter_private_keys

    #################################
    ###### Getter Functions #########
    #################################

    def get_external_server_ports(self):
        """Returns the list of ports on which external servers are running."""
        return [port for port in self.external_server_ports]
        
    def get_authority_center_public_key(self):
        """Returns the public key of the authority center."""
        return self.authority_center_public_key
        
    def get_voter_public_keys(self):
        """Returns the dictionary of voter public keys."""
        return self.voter_public_keys
        
    def get_voter_ids(self):
        """Returns the list of voter IDs."""
        return self.voter_ids
        
    ######################################
    ###### External Server Process #######
    ######################################

    def start_external_servers(self):
        """
        Starts external servers on different ports. Each server runs in a separate thread.
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
        Retrieves data from external servers.

        Args:
            server_ports (list): List of external server ports.

        Returns:
            dict: Data retrieved from each server.
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
        Sends a request to external servers to delete stored data.

        Args:
            server_ports (list): List of external server ports.
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
        Starts the authority center server to handle requests from the voting terminal.
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
        Handles communication with the voting terminal, processes requests, and sends responses.

        Args:
            conn (socket): Socket connection to the voting terminal.
            addr (tuple): Address of the voting terminal.
        """
        try:
            request = receive_large_data(conn)
            
            if request['command'] == 'GET_AUTHORITY_CENTER_PUBLIC_INFO':
                # Send the public key, voter IDs and the external server adresses to the voting terminal
                transformed_voter_public_keys = {
                    key: {'curve': str(value.curve), 'point_x': int(value.pointQ.x), 'point_y': int(value.pointQ.y)}
                    for key, value in self.voter_public_keys.items()
                }
                response = {
                    'voters_id': self.voter_ids,
                    'external_server_ports': self.external_server_ports,
                    'authority_center_public_key': {
                        'curve': str(self.authority_center_public_key.curve),
                        'point_x': int(self.authority_center_public_key.pointQ.x),
                        'point_y': int(self.authority_center_public_key.pointQ.y)
                    }
                }
            
            elif request['command'] == 'SEND_TERMINAL_PUBLIC_INFO':
                # Receive public keys from the voting terminal
                info = request['data']
                response = {"status": "received", "info": info}
                self.signing_public_key = self.decryptor.reconstruct_ECC_key(info['signing_public_key']['curve'], info['signing_public_key']['point_x'], info['signing_public_key']['point_y'])
                self.voting_terminal_public_key = self.decryptor.reconstruct_ECC_key(info['voting_terminal_public_key']['curve'], info['voting_terminal_public_key']['point_x'], info['voting_terminal_public_key']['point_y'])
                print(f"Received the signing and the voting terminal public key from the voting terminal.")
            
            elif request['command'] == 'GET_VOTER_ID':
                # Process request to verify a voter's identity
                encrypted_id = request['encrypted_id']
                iv_id = request['iv']
                signature_id = request['signature']
                voter_id = self.decryptor.decrypt_and_verify_voter_id(self.voting_terminal_public_key, self.signing_public_key, encrypted_id, iv_id, signature_id)
                if voter_id and voter_id in self.voter_ids:
                    public_key = self.voter_public_keys[voter_id]
                    response = {
                        'valid': True,
                        'public_key': {
                            'curve': str(public_key.curve),
                            'point_x': int(public_key.pointQ.x),
                            'point_y': int(public_key.pointQ.y)
                        }
                    }
                else:
                    response = {'valid': False}
            
            send_large_data(conn, response)
        except Exception as e:
            print(f"Error in handle_voting_terminal: {e}")
        finally:
            conn.close()
            
    #################################
    ##### Main Result Process #######
    #################################
    
    def process_election_results(self):
        """
        Processes the election results, including verification, decryption, and final tally.
        
        Returns:
            bool: True if the election results were processed successfully, False otherwise.
        """
        try:
            # Retrieve shares from external servers
            all_shares = self.retrieve_data_from_external_servers(self.external_server_ports)
            
            # Verify signatures on the shares
            is_signed = {
                port: all([self.decryptor.verify_signature(self.signing_public_key, element[2], element[4]) for element in data])
                for port, data in all_shares.items()
            }

            # Check for too many corrupted shares
            if list(is_signed.values()).count(False) >= self.threshold:
                print("\033[91mElection corrupted: Too many corrupted shares.\033[0m")
                return False

            # Select valid servers to reconstruct the vote
            valid_server_ports = [port for port, valid in is_signed.items() if valid]
            selected_server_ports = random.sample(valid_server_ports, self.threshold)
            shares_per_vote = self.retrieve_data_from_external_servers(selected_server_ports)
            shares_per_vote = list(shares_per_vote.values())
            shares_per_vote = [list(share_tuple) for share_tuple in zip(*shares_per_vote)]
            
            # Decrypt shares and reconstruct the vote
            decrypted_shares = [
                [
                    self.decryptor.bytes_to_tuple(self.decryptor.decrypt_vote(self.voting_terminal_public_key, self.voter_private_keys[self.decryptor.bytes_to_str(self.decryptor.decrypt_vote(self.voting_terminal_public_key, self.authority_center_private_key, share_data[0], share_data[1]))], share_data[2], share_data[3]
                    ))
                    for share_data in share_tuple
                ]
                for share_tuple in shares_per_vote
            ]
            
            self.participation = len(decrypted_shares)
            for share_tuple in decrypted_shares:
                reconstructed_vote = reconstruct_secret(share_tuple, self.prime)
                decoded_vote = self.decryptor.decode_vote_result(reconstructed_vote, self.total_vote_bits, self.num_candidates)
                self.candidate_results = [
                    current + new for current, new in zip(self.candidate_results, decoded_vote)
                ]

            return True
        except Exception as e:
            print(f"\033[91mAn error occurred during election result processing: {e}\033[0m")
            return False


if __name__ == "__main__":
    """
    Main execution flow of the Authority Center.
    Parses command-line arguments, initializes the Authority Center, starts external servers,
    and manages the election process.
    """
    # Set up command-line argument parsing with default values
    parser = argparse.ArgumentParser(description="Election System Parameters")
    parser.add_argument("--num_voters", type=int, default=10, help="Number of voters (default: 10)")
    parser.add_argument("--candidates", type=str, default="Alice,Bob,Charles,David", help="Comma-separated list of candidate names (default: Candidate1,Candidate2,Candidate3,Candidate4)")
    parser.add_argument("--num_shares", type=int, default=4, help="Number of shares for secret sharing (default: 4)")
    parser.add_argument("--threshold", type=int, default=3, help="Threshold for secret reconstruction (default: 3)")
    parser.add_argument("--duration", type=int, default=1, help="Election duration in minutes (default: 1)")
    parser.add_argument("--buffer_size", type=int, default=16384, help="Buffer size for data transmission (default: 16384)")
    
    args = parser.parse_args()
    
    # Parameters Setup from command line arguments
    candidate_names = args.candidates.split(",")
    num_voters = args.num_voters
    num_candidates = len(candidate_names)
    
    num_bits_per_vote = math.floor(math.log2(num_voters)) + 1  # Bits needed to represent each vote
    total_vote_bits = num_bits_per_vote * num_candidates  # Total number of bits to represent all votes
    
    prime_number = nextprime(2**(total_vote_bits - num_bits_per_vote) * (num_candidates + 1))  # Large prime number
    num_shares = args.num_shares
    threshold = args.threshold
    election_duration = timedelta(minutes=args.duration)
    buffer_size = args.buffer_size
    
    print(f"\033[96mWelcome to the Authority center!\033[0m\n")
    
    # Initialize the Central Server
    authority_center = AuthorityCenter(num_voters, num_candidates, num_bits_per_vote, num_shares, threshold, prime_number, buffer_size)
    
    print(f"\033[93mInitialization of the external servers...\033[0m")
    authority_center.start_external_servers()
    
    # Start the central server in a separate thread
    server_thread = threading.Thread(target=authority_center.start_authority_center)
    server_thread.start()
    
    # Start the election
    election_start = datetime.now()
    print(f"\nElection opened on: {election_start.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Print election details
    print("\nElection Details:")
    print(f"Number of registered Voters: {num_voters}")
    print(f"Number of Candidates: {num_candidates}")
    
    # Display voter IDs
    print("\nVoter IDs:")
    for voter_id in authority_center.get_voter_ids():
        print(voter_id)
    
    # Set a deadline for the election
    election_deadline = election_start + election_duration
    print(f"\nElection will close at: {election_deadline.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Countdown timer
    while datetime.now() < election_deadline:
        time_remaining = election_deadline - datetime.now()
        print(f"Time remaining until election closes: {time_remaining}", end='\r')
        time.sleep(1)
    
    print(f"\033[92mElection closed. Processing results...\033[0m\n")
    successful = authority_center.process_election_results()
    
    if successful:
        participation_rate = (authority_center.participation / num_voters * 100)
        print(f"\033[92mParticipation: {participation_rate:.2f}%\033[0m")
        print("\033[92mFinal Candidate Results:\033[0m")
        for i, candidate in enumerate(candidate_names):
            print(f"    \033[93m{candidate} : \033[92m{authority_center.candidate_results[i]}\033[0m")
    else:
        print("\033[91mElection processing failed due to errors.\033[0m")

    # Clean up external servers
    authority_center.delete_data_from_external_servers(authority_center.get_external_server_ports())
    
    # Terminate the program
    os._exit(0)
