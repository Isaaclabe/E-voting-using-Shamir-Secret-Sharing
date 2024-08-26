import socket
import pickle
import math
import random
import struct
import argparse
from sympy import nextprime

from utils_server import send_large_data, receive_large_data
from utils_crypto import Encryptor
from utils_shamir import generate_random_coefficients, evaluate_polynomial_at


class VotingTerminal:
    """
    The VotingTerminal class represents a voting terminal in the election system.
    It handles communication with the authority center, manages voter authentication,
    and processes vote casting, including generating shares using Shamir's Secret Sharing.
    """
    def __init__(self, num_candidates, num_bits, num_shares, threshold, prime, buffer_size):
        self.num_candidates = num_candidates
        self.candidates_index = [i for i in range(1, num_candidates + 1)]
        self.num_bits_per_vote = num_bits
        self.num_shares = num_shares
        self.threshold = threshold
        self.prime = prime
        self.buffer_size = buffer_size
        
        self.voters_who_voted = set()
        self.authority_center_ip = 'localhost'
        self.authority_center_port = 8000
        
        self.encryptor = Encryptor()
        
        # Retrieve initial public information from the authority center
        self.voter_ids, self.authority_center_public_key, self.external_server_ports = self.get_public_info_from_authority_center()
        self.signing_private_key, self.signing_public_key = self.encryptor.get_signing_keys()
        self.voting_terminal_private_key, self.voting_terminal_public_key = self.encryptor.get_voting_terminal_private_key()

        # Send public keys to the authority center
        self.send_public_keys_to_authority_center()
        
    ###########################
    ###### Get Functions ######
    ###########################

    def get_external_server_ports(self):
        """Returns the list of ports for external servers."""
        return self.external_server_ports
        
    def get_signing_public_key(self):
        """Returns the signing public key."""
        return self.signing_public_key
        
    def get_voting_terminal_public_key(self):
        """Returns the voting terminal public key."""
        return self.voting_terminal_public_key
    
    def get_voter_ids(self):
        """Returns the list of voter IDs."""
        return self.voter_ids
        
    ##########################################
    ###### Server Communication Process ######
    ##########################################
    
    def send_public_keys_to_authority_center(self):
        """
        Sends the public keys (signing and voting terminal) to the authority center for registration.
        """
        public_keys = {
            'signing_public_key': {
                'curve': str(self.signing_public_key.curve),
                'point_x': int(self.signing_public_key.pointQ.x),
                'point_y': int(self.signing_public_key.pointQ.y)
            },
            'voting_terminal_public_key': {
                'curve': str(self.voting_terminal_public_key.curve),
                'point_x': int(self.voting_terminal_public_key.pointQ.x),
                'point_y': int(self.voting_terminal_public_key.pointQ.y)
            }
        }
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.authority_center_ip, self.authority_center_port))
            request = {'command': 'SEND_TERMINAL_PUBLIC_INFO', 'data': public_keys}
            send_large_data(sock, request)
            response = receive_large_data(sock)

    def send_voter_id_to_authority_center(self, voter_id):
        """
        Encrypts and sends the voter ID to the authority center to verify voter eligibility.

        Args:
            voter_id (str): The ID of the voter.

        Returns:
            tuple: A tuple indicating whether the voter ID is valid and the public key of the voter.
        """
        self.encrypted_id, self.iv_id, self.signature_id = self.encryptor.encrypt_and_sign(self.authority_center_public_key, voter_id)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.authority_center_ip, self.authority_center_port))
            request = {
                'command': 'GET_VOTER_ID',
                'encrypted_id': self.encrypted_id,
                'iv': self.iv_id,
                'signature': self.signature_id
            }
            send_large_data(sock, request)
            response = receive_large_data(sock)
            if response['valid']:
                public_key = self.encryptor.reconstruct_ECC_key(response['public_key']['curve'], response['public_key']['point_x'], response['public_key']['point_y'])
                return True, public_key
            else:
                return False, None

    def get_public_info_from_authority_center(self):
        """
        Retrieves public information such as voter IDs, authority center public key, and external server ports from the authority center.

        Returns:
            tuple: A tuple containing voter IDs, authority center public key, and external server ports.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.authority_center_ip, self.authority_center_port))
            request = {'command': 'GET_AUTHORITY_CENTER_PUBLIC_INFO'}
            send_large_data(sock, request)
            response = receive_large_data(sock)
            
            external_server_ports = response['external_server_ports']
            
            authority_center_public_key_info = response['authority_center_public_key']
            authority_center_public_key = self.encryptor.reconstruct_ECC_key(authority_center_public_key_info['curve'], authority_center_public_key_info['point_x'], authority_center_public_key_info['point_y'])
            
            voter_ids = response['voters_id']
            
            print(f"Received the external addresses and the authority public key from the Authority center.\n")
            
            return voter_ids, authority_center_public_key, external_server_ports

    def send_shares_to_external_servers(self, shares):
        """
        Sends encrypted shares to the external servers for secure storage.

        Args:
            shares (list): A list of shares to send to the external servers.
        """
        def send_data_to_server(server_port, data_tuple):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                try:
                    sock.connect(('localhost', server_port))
                    request = {'command': 'STORE_DATA', 'data': data_tuple}
                    send_large_data(sock, request)
                    response = receive_large_data(sock)
                    return response
                except Exception as e:
                    print(f"Error sending data to server: {e}")
                    return None
        
        for i, share in enumerate(shares):
            port = self.external_server_ports[i % len(self.external_server_ports)]
            send_data_to_server(port, share)
        
        print(f"Data shared through external servers...")

    ###########################################
    ###### Shamir Secret Sharing Process ######
    ###########################################
    
    def generate_vote_shares(self, voter_id: str, encoded_vote: int, voter_public_key) -> list:
        """
        Generates encrypted shares of a vote using Shamir's Secret Sharing scheme.

        Args:
            voter_id (str): The ID of the voter casting the vote.
            encoded_vote (int): The encoded vote.
            voter_public_key: The public key of the voter for encrypting the shares.

        Returns:
            list: A list of encrypted shares.
        """
        coefficients = generate_random_coefficients(encoded_vote, self.threshold, self.prime)
        shares = []
        for i in range(1, self.num_shares + 1):
            x = i
            y = evaluate_polynomial_at(x, coefficients, self.prime)
            encrypted_share, iv_share, signature_share = self.encryptor.encrypt_and_sign(voter_public_key, (x, y))
            shares.append((self.encrypted_id, self.iv_id, encrypted_share, iv_share, signature_share))
        return shares

    ##################################
    ###### Main Voting Process #######
    ##################################
    
    def cast_vote(self, voter_id: str, candidate_index: int):
        """
        Handles the process of casting a vote by a voter.

        Args:
            voter_id (str): The ID of the voter.
            candidate_index (int): The index of the chosen candidate.

        Returns:
            bool: True if the vote was cast successfully, False otherwise.
        """
        # Check if the voter has already voted
        if voter_id in self.voters_who_voted:
            print(f"\033[91mVoter with ID {voter_id} has already voted. Voting again is not allowed.\n\033[0m")
            return False

        # Validate the voter ID
        is_valid, voter_public_key = self.send_voter_id_to_authority_center(voter_id)
        if not is_valid:
            print(f"\033[91mInvalid voter ID {voter_id}. Please enter a valid voter ID.\n\033[0m")
            return False

        # Check if the candidate index is valid
        if candidate_index not in self.candidates_index:
            print(f"\033[91mInvalid candidate index {candidate_index}. Please select a valid candidate.\n\033[0m")
            return False

        # Proceed with the voting process if the voter has not voted yet
        encoded_vote = 1 << ((self.num_candidates - candidate_index) * self.num_bits_per_vote)
        shares = self.generate_vote_shares(voter_id, encoded_vote, voter_public_key)
        self.send_shares_to_external_servers(shares)

        # Mark the voter as having voted
        self.voters_who_voted.add(voter_id)
        print(f"\033[92mVoter with ID {voter_id} has successfully cast their vote.\n\033[0m")
        
        return True


if __name__ == "__main__":
    """
    Main execution flow for the Voting Terminal.
    Parses command-line arguments, initializes the Voting Terminal, and handles the voting process.
    """
    # Set up command-line argument parsing with default values
    parser = argparse.ArgumentParser(description="\033[96mVoting System Parameters\033[0m")
    parser.add_argument("--num_voters", type=int, default=10, help="Number of voters (default: 10)")
    parser.add_argument("--candidates", type=str, default="Alice,Bob,Charles,David", help="Comma-separated list of candidate names (default: Alice,Bob,Charles,David)")
    parser.add_argument("--num_shares", type=int, default=4, help="Number of shares for secret sharing (default: 4)")
    parser.add_argument("--threshold", type=int, default=3, help="Threshold for secret reconstruction (default: 3)")
    parser.add_argument("--mode", type=str, choices=["manual", "automatic"], default="automatic", help="Voting mode, 'manual' or 'automatic' (default: automatic)")
    parser.add_argument("--N", type=int, default=2, help="Number of voters in manual mode (default: 2)")
    parser.add_argument("--buffer_size", type=int, default=16384, help="Buffer size for data transmission (default: 16384)")

    args = parser.parse_args()

    # Parameters Setup from command line arguments
    candidate_names = args.candidates.split(",")
    num_voters = args.num_voters
    num_candidates = len(candidate_names)
    
    num_bits_per_vote = math.floor(math.log2(num_voters)) + 1
    total_vote_bits = num_bits_per_vote * num_candidates
    
    prime_number = nextprime(2**(total_vote_bits - num_bits_per_vote) * (num_candidates + 1))  
    num_shares = args.num_shares
    threshold = args.threshold
    mode = args.mode
    N = args.N
    buffer_size = args.buffer_size
    
    # Welcome and instructions
    print("\n\033[96m=== Welcome to the Election! ===\033[0m\n")
    print(f"\033[93mYou can vote for:\033[0m")
    for i, candidate in enumerate(candidate_names):
        print(f"   \033[93m{i+1}: {candidate}\033[0m")

    print("\n\033[94mInitializing the Voting Terminal...\033[0m")
    
    # Initialize the Voting Terminal
    voting_terminal = VotingTerminal(num_candidates, num_bits_per_vote, num_shares, threshold, prime_number, buffer_size)

    print("\033[92mVoting Terminal is ready!\033[0m\n")

    # Example voting process
    if mode == "manual":
        print("\033[96mManual Voting Mode\033[0m\n")
        for _ in range(N):
            while True:
                voter_id = input("\033[94mEnter your voter ID: \033[0m")
                candidate_index = int(input("\033[94mEnter your vote (index of the candidate): \033[0m"))
                vote_status = voting_terminal.cast_vote(voter_id, candidate_index)
                if vote_status:
                    break
                else:
                    print("\033[91mInvalid vote. Please try again.\033[0m\n")
    elif mode == "automatic":
        print("\033[96mAutomatic Voting Mode\033[0m\n")
        vote_cast = [random.randint(1, num_candidates) for _ in range(random.randint(num_voters // 2, num_voters))]
        vote_result = [vote_cast.count(i) for i in range(1, num_candidates + 1)]
        voter_ids = voting_terminal.get_voter_ids()
        for i, voter_id in enumerate(random.sample(voter_ids, len(vote_cast))):
            voting_terminal.cast_vote(voter_id, vote_cast[i])
            
        print("\033[92mThe true vote results:\033[0m")
        for i, candidate in enumerate(candidate_names):
            print(f"    \033[93m{candidate} : \033[92m{vote_result[i]}\033[0m")
    else:
        print("\033[91mError! Invalid voting mode selected. Please select 'manual' or 'automatic'.\033[0m")
