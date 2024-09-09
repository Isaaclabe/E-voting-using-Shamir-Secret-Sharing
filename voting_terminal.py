import socket
import pickle
import math
import random
import struct
import argparse
from sympy import nextprime, mod_inverse
import struct

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from phe import paillier

from utils_server import send_large_data, receive_large_data


class VotingTerminal:
    def __init__(self, num_candidates, num_bits, num_shares, threshold, prime, buffer_size):
        """
        Initializes the VotingTerminal with the specified number of candidates, number of bits per vote,
        the number of shares, threshold for secret sharing, a prime number for modular arithmetic,
        and a buffer size for data transfer. This setup handles the preparation for vote casting and
        secret sharing in a secure voting protocol.
        
        Args:
            num_candidates (int): Total number of candidates in the election.
            num_bits (int): Number of bits used for encoding each vote.
            num_shares (int): Number of shares to be generated for secret sharing.
            threshold (int): Minimum number of shares required to reconstruct the vote.
            prime (int): Prime number used for modular arithmetic in secret sharing.
            buffer_size (int): Buffer size for data transmission during network operations.
        """
        self.num_candidates = num_candidates
        self.candidates_index = [i for i in range(1, num_candidates + 1)]
        self.num_bits_per_vote = num_bits
        self.num_shares = num_shares
        self.threshold = threshold
        self.prime = prime
        self.buffer_size = buffer_size
        
        self.voters_who_voted = set()
        self.authority_center_ip = '127.0.0.1'
        self.authority_center_port = 8000
        
        # Generate the signing and voting terminal ECC public-private key pairs
        self.signing_private_key, self.signing_public_key = self.generate_ECC_keys()
        self.VT_private_key, self.VT_public_key = self.generate_ECC_keys()
        
        # Retrieve the voter IDs, external server ports, and the public key of the Authority Center
        # Note: In a real voting scenario, voter IDs would not normally be retrieved by the terminal.
        self.voter_ids, self.external_server_ports, self.AC_public_key = self.get_public_info_from_AC()
        
        # Send the signing and voting terminal public keys to the Authority Center
        self.send_PubKeys_to_AC()
        
        
    ###########################
    ###### Get Functions ######
    ###########################

    def get_external_server_ports(self):
        """
        Returns the list of external server ports.
        
        Returns:
            list: A list of external server ports.
        """
        return self.external_server_ports
        
    def get_signing_public_key(self):
        """
        Returns the public key used for signing.

        Returns:
            ECC key object: The ECC public key used for signing.
        """
        return self.signing_public_key
        
    def get_voting_terminal_public_key(self):
        """
        Returns the public key of the Voting Terminal.

        Returns:
            ECC key object: The ECC public key of the Voting Terminal.
        """
        return self.VT_public_key
    
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
    
    def generate_homomorphic_keys(self):
        """
        Generates a public-private key pair for homomorphic encryption using the Paillier cryptosystem.
        
        Returns:
            tuple: The private and public Paillier keys.
        """
        public_key, private_key = paillier.generate_paillier_keypair()
        return private_key, public_key
    
    def generate_ECC_keys(self):
        """
        Generates a public-private key pair using Elliptic Curve Cryptography (ECC).
        
        Returns:
            tuple: The ECC private key and the corresponding public key.
        """
        private_key = ECC.generate(curve='P-256')
        public_key = private_key.public_key()
        return private_key, public_key
        
    def reconstruct_homomorphic_public_key(self, public_key_n):
        """
        Reconstructs a homomorphic public key using the modulus 'n' from the Paillier cryptosystem.
        
        Args:
            public_key_n (int): The modulus 'n' of the Paillier public key.
            
        Returns:
            paillier.PaillierPublicKey: The reconstructed Paillier public key.
        """
        return paillier.PaillierPublicKey(public_key_n)
        
    def reconstruct_homomorphic_private_key(self, public_key, private_key_dict):
        """
        Reconstructs a homomorphic private key using the public key and a dictionary of private key components.

        Args:
            public_key (paillier.PaillierPublicKey): The Paillier public key corresponding to the private key.
            private_key_dict (dict): A dictionary containing the components 'lambda' and 'mu' of the private key.
            
        Returns:
            paillier.PaillierPrivateKey: The reconstructed Paillier private key.
        """
        return paillier.PaillierPrivateKey(public_key=public_key, lmbda=private_key_dict['lambda'], mu=private_key_dict['mu'])
        
    def reconstruct_ECC_key(self, curve, point_x, point_y):
        """
        Reconstructs an ECC public key using the curve and its point coordinates.

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
    def string_to_int(self, s):
        """
        Converts a string to an integer by encoding the string into bytes and then interpreting
        those bytes as a large integer.

        Args:
            s (str): The input string to be converted.
            
        Returns:
            int: The integer representation of the string.
        """
        return int.from_bytes(s.encode('utf-8'), 'big')
    
    def generate_unique_random_integer(self, bit_length=16, generated_integers=None):
        """
        Generates a unique random integer of the specified bit length, ensuring that it has not
        been generated before.
        
        Args:
            bit_length (int): The length of the generated integer in bits. Default is 16 bits.
            generated_integers (set): A set of integers that have already been generated, ensuring uniqueness.
            
        Returns:
            int: A unique random integer of the specified bit length.
        """
        if generated_integers is None:
            generated_integers = set()

        while True:
            random_integer = random.getrandbits(bit_length)
            if random_integer not in generated_integers:
                generated_integers.add(random_integer)
                return random_integer
        
    def convert_data_to_bytes(self, data):
        """
        Converts various types of data (tuple, integer, string) into their byte representation.
        
        Args:
            data: The data to be converted to bytes. Can be a tuple, integer, or string.
        
        Returns:
            bytes: The byte representation of the input data.
            None: If the data type is not supported.
        """
        if isinstance(data, tuple):
            format_string = 'q' * len(data)
            return struct.pack(format_string, *data)
        elif isinstance(data, int):
            return struct.pack('q', data)
        elif isinstance(data, str):
            return data.encode('utf-8')
        else:
            print(f"Unsupported data type: {type(data)}")
            return None

          
    #########################################################
    ###### Communication with Authority Center Process ######
    #########################################################
    
    def send_PubKeys_to_AC(self):
        """
        Sends the Voting Terminal's public keys (signing and voting terminal public key) to the Authority Center.
        """
        public_keys = {
            'signing_public_key': {
                'curve': str(self.signing_public_key.curve),
                'point_x': int(self.signing_public_key.pointQ.x),
                'point_y': int(self.signing_public_key.pointQ.y)
            },
            'VT_public_key': {
                'curve': str(self.VT_public_key.curve),
                'point_x': int(self.VT_public_key.pointQ.x),
                'point_y': int(self.VT_public_key.pointQ.y)
            }
        }
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.authority_center_ip, self.authority_center_port))
            
            request = {'command': 'VT_SEND_PUBLIC_KEYS', 'data': public_keys}
            
            send_large_data(sock, request)
            response = receive_large_data(sock)
            
    def send_homomorphic_PubKey_to_AC(self, homomorphic_public_key):
        """
        Sends the homomorphic public key to the Authority Center.
        
        Args:
            homomorphic_public_key: The homomorphic public key generated by the Voting Terminal.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.authority_center_ip, self.authority_center_port))
            
            request = {'command': 'VT_SEND_HOMOMORPHIC_PUBLIC_KEY', 'data': homomorphic_public_key.n}
            
            send_large_data(sock, request)
            response = receive_large_data(sock)
        
    def get_encrypted_IDs_from_AC(self):
        """
        Retrieves the list of encrypted voter IDs from the Authority Center.
        
        Returns:
            list or bool: A list of reconstructed encrypted IDs, or False if the election is closed.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.authority_center_ip, self.authority_center_port))
            
            request = {'command': 'AC_SEND_ENCRYPTED_IDS'}
            
            send_large_data(sock, request)
            response = receive_large_data(sock)
            
            encrypted_id_list = response['encrypted_voters_id']
            is_close = response['is_close']
            
            if is_close is True:
                return False
            else:
                reconstructed_encrypted_id_list = [paillier.EncryptedNumber(self.homomorphic_public_key, encrypted_id[0], encrypted_id[1]) for encrypted_id in encrypted_id_list]
                return reconstructed_encrypted_id_list

    def get_voter_PubKey_from_AC(self, random_id):
        """
        Retrieves the public key of a voter from the Authority Center using the voter's random ID.
        
        Args:
            random_id (int): The unique random ID assigned to the voter.
        
        Returns:
            ECC.EccKey: The voter's ECC public key reconstructed from the AC's response.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.authority_center_ip, self.authority_center_port))
            
            request = {'command': 'AC_SEND_VOTER_PUBLIC_KEY', 'data': random_id}
            
            send_large_data(sock, request)
            response = receive_large_data(sock)
            
            public_key = self.reconstruct_ECC_key(response['public_key']['curve'], response['public_key']['point_x'], response['public_key']['point_y'])
            return public_key

    def get_public_info_from_AC(self):
        """
        Retrieves public information from the Authority Center (AC), including:
            - A list of voter IDs.
            - External server ports used for secure storage of vote shares.
            - The public key of the Authority Center.
                
        Returns:
            tuple: A tuple containing the list of voter IDs, external server ports, and the AC's public key.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.authority_center_ip, self.authority_center_port))
            
            request = {'command': 'AC_SEND_PUBLIC_INFO'}
            
            send_large_data(sock, request)
            response = receive_large_data(sock)
            
            voter_ids = response['voters_id']
            external_server_ports = response['external_server_ports']
            AC_public_key = response['AC_public_key']
            AC_public_key = self.reconstruct_ECC_key(AC_public_key['curve'], AC_public_key['point_x'], AC_public_key['point_y'])
            
            print(f"\033[0;35mReceived the external addresses from the Authority center!\033[0m\n")
            print(f"\033[0;35mReceived the authority public key from the Authority center!\033[0m\n")
            return voter_ids, external_server_ports, AC_public_key


    #########################################################
    ###### Communication with External Servers Process ######
    #########################################################
    
    def send_shares_to_external_servers(self, shares):
        """
        Distributes the generated shares to external servers for secure storage.

        Args:
            shares (list): A list of shares to be sent to external servers.
        """
        
        def send_data_to_server(server_port, data_tuple):
            """
            Sends a given data tuple to the specified server over a socket connection.

            Args:
                server_port (int): The port number of the external server to which the data will be sent.
                data_tuple (tuple): The data (in tuple format) that will be sent to the external server.
            
            Returns:
                response: The response received from the external server after the data is sent.
            """
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect(('localhost', server_port))
                
                request = {'command': 'STORE_DATA', 'data': data_tuple}
                
                send_large_data(sock, request)
                response = receive_large_data(sock)
                return response
        
        for i, share in enumerate(shares):
            port = self.external_server_ports[i % len(self.external_server_ports)]
            send_data_to_server(port, share)


    #################################
    ###### ID authentification ######
    #################################

    def verify_eligibility_id(self, voter_id):
        """
        Verifies the eligibility of a voter using homomorphic encryption by comparing their encrypted voter ID
        against a list of encrypted eligible IDs obtained from the Authority Center.

        Args:
            voter_id (str): The voter's ID, typically in string format, which will be checked for eligibility.
        
        Returns:
            tuple: If the ID is valid, it returns the voter's public key and a new unique random ID.
                   If the ID is invalid, it returns (False, None). If there is a problem with retrieving the encrypted list,
                   it returns (False, "close").
        """
        int_voter_id = self.string_to_int(voter_id)
        self.homomorphic_private_key, self.homomorphic_public_key = self.generate_homomorphic_keys()
        
        self.send_homomorphic_PubKey_to_AC(self.homomorphic_public_key)
        reconstructed_encrypted_id_list = self.get_encrypted_IDs_from_AC()
        
        if reconstructed_encrypted_id_list is False:
            return False, "close"
        else:
            encrypted_voter_id = self.homomorphic_public_key.encrypt(int_voter_id)
            encrypted_differences = [encrypted_id - encrypted_voter_id for encrypted_id in reconstructed_encrypted_id_list]
            is_id_present = any(self.homomorphic_private_key.decrypt(diff) == 0 for diff in encrypted_differences)
            if is_id_present:
                new_random_id = self.generate_unique_random_integer()
                public_voter_key = self.get_voter_PubKey_from_AC(new_random_id)
                return public_voter_key, new_random_id
            else:
                return False, None


    ############################
    ###### Sign Functions ######
    ############################
        
    def sign_data(self, data):
        """
        Signs the given data using the Elliptic Curve Digital Signature Algorithm

        Args:
            data (bytes): The data to be signed. This should be in bytes format, typically a hashed message.
        
        Returns:
            bytes: The digital signature generated from the private key, which can be used for verification.
        """
        hash_obj = SHA256.new(data)
        signer = DSS.new(self.signing_private_key, 'fips-186-3')
        signature = signer.sign(hash_obj)
        return signature


    ##################################
    ###### Encryption Functions ######
    ##################################
        
    def encrypt_data(self, encrypt_public_key, data):
        """
        Encrypts the provided data using ECDH key exchange to derive a shared secret,
        and AES in CBC mode for encryption.
        
        Args:
            encrypt_public_key (ECC.EccKey): The public ECC key used to encrypt the data, allowing for secure shared key generation.
            data (tuple, int, or str): The data to be encrypted. This can be a tuple, integer, or string.
        
        Returns:
            tuple: The encrypted data (in bytes) and the initialization vector (IV) used for the AES encryption.
        """
        data_bytes = self.convert_data_to_bytes(data)
        shared_secret_point = encrypt_public_key.pointQ * self.VT_private_key.d
        shared_secret_bytes = int(shared_secret_point.x).to_bytes(32, byteorder='big')
        aes_key = SHA256.new(shared_secret_bytes).digest()
        
        cipher = AES.new(aes_key, AES.MODE_CBC)
        iv = cipher.iv
        encrypted_data = cipher.encrypt(pad(data_bytes, AES.block_size))
        return encrypted_data, iv


    ###########################################
    ###### Shamir Secret Sharing Process ######
    ###########################################
    
    def generate_random_coefficients(self, encoded_vote, threshold, prime):
        """
        Generates random coefficients for a polynomial used in Shamir's Secret Sharing scheme.

        Args:
            encoded_vote (int): The encoded vote that forms the constant term of the polynomial.
            threshold (int): The minimum number of shares required to reconstruct the vote.
            prime (int): A prime number used for modular arithmetic.

        Returns:
            list: A list of coefficients for the polynomial, with the encoded vote as the constant term.
        """
        coefficients = [encoded_vote]
        for _ in range(threshold - 1):
            coefficients.append(random.randint(1, prime - 1))
        return coefficients

    def evaluate_polynomial_at(self, x, coefficients, prime):
        """
        Evaluates a polynomial at a given x-coordinate using modular arithmetic.
        
        Args:
            x (int): The x-coordinate at which to evaluate the polynomial.
            coefficients (list): The list of polynomial coefficients.
            prime (int): A prime number used for modular arithmetic.

        Returns:
            int: The result of evaluating the polynomial at the given x-coordinate, mod prime.
        """
        result = 0
        for i, coeff in enumerate(coefficients):
            result += coeff * (x ** i)
            result %= prime
        return result
    
    def generate_vote_shares(self, voter_id, encoded_vote, voter_public_key, new_random_id):
        """
        Generates encrypted vote shares using Shamir's Secret Sharing and encrypts the shares with the voter's public key.

        Args:
            voter_id (str): The ID of the voter.
            encoded_vote (int): The encoded vote to be shared.
            voter_public_key (ECC.EccKey): The public key of the voter, used to encrypt their vote shares.
            new_random_id (int): A new unique random ID generated for the voter.

        Returns:
            list: A list of tuples, where each tuple contains:
                  - Encrypted voter ID and its initialization vector (IV).
                  - Encrypted vote share and its IV.
                  - Signature of the encrypted vote share.
        """
        coefficients = self.generate_random_coefficients(encoded_vote, self.threshold, self.prime)
        shares = []
        for i in range(1, self.num_shares + 1):
            x = i
            y = self.evaluate_polynomial_at(x, coefficients, self.prime)
            encrypted_id, iv_id = self.encrypt_data(self.AC_public_key, new_random_id)
            encrypted_share, iv_share = self.encrypt_data(voter_public_key, (x, y))
            signature_share = self.sign_data(encrypted_share)
            shares.append((encrypted_id, iv_id, encrypted_share, iv_share, signature_share))
        return shares


    ##################################
    ###### Main Voting Process #######
    ##################################
    
    def cast_vote(self, voter_id, candidate_index):
        """
        Allows a voter to cast their vote for a specified candidate, provided that the voter is eligible
        and the election is still open. The vote is encrypted and distributed as shares using Shamir's Secret Sharing.
        
        Args:
            voter_id (str): The ID of the voter attempting to cast their vote.
            candidate_index (int): The index of the candidate for whom the vote is being cast.

        Returns:
            bool: True if the vote is successfully cast, False otherwise.
        """
        # Check if the voter has already voted
        if voter_id in self.voters_who_voted:
            print(f"\n\033[91mYou already voted. Voting again is not allowed.\033[0m")
            return False

        # Legitimate the voter ID
        voter_public_key, new_random_id = self.verify_eligibility_id(voter_id)
        if voter_public_key is False and new_random_id == "close":
            print(f"\n\033[91mYou cannot vote, the election is close!\033[0m")
            return "close"
        elif voter_public_key is False and new_random_id is None:
            print(f"\n\033[91mInvalid voter ID {voter_id}. Please enter a valid voter ID.\033[0m")
            return False

        # Check if the vote is valid
        if candidate_index not in self.candidates_index:
            print(f"\n\033[91mInvalid candidate index {candidate_index}. Please select a valid candidate.\033[0m")
            return False

        # Cast the vote
        encoded_vote = 1 << ((self.num_candidates - candidate_index) * self.num_bits_per_vote)
        shares = self.generate_vote_shares(voter_id, encoded_vote, voter_public_key, new_random_id)
        self.send_shares_to_external_servers(shares)

        # Mark the voter as having voted
        self.voters_who_voted.add(voter_id)
        print(f"\n\033[92mYour new ID is {new_random_id}, and you successfully cast your vote: {candidate_index}.\033[0m")
        return True
        
        
        

if __name__ == "__main__":
    ######################################
    #### Setup command-line argument #####
    ######################################
    
    parser = argparse.ArgumentParser(description="\033[96mVoting System Parameters\033[0m")
    parser.add_argument("--num_voters", type=int, default=10, help="Number of voters (default: 10)")
    parser.add_argument("--candidates", type=str, default="Alice,Bob,Charles,David", help="Comma-separated list of candidate names (default: Alice,Bob,Charles,David)")
    parser.add_argument("--num_shares", type=int, default=10, help="Number of shares for secret sharing (default: 4)")
    parser.add_argument("--threshold", type=int, default=7, help="Threshold for secret reconstruction (default: 3)")
    parser.add_argument("--mode", type=str, choices=["manual", "automatic"], default="automatic", help="Voting mode, 'manual' or 'automatic' (default: automatic)")
    parser.add_argument("--N", type=int, default=2, help="Number of voters in manual mode (default: 2)")
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
    mode = args.mode
    N = args.N
    buffer_size = args.buffer_size
    
    
    ######################################
    ###### Setup the Voting Terminal #####
    ######################################
    
    print(f"\033[96m========================================")
    print(f"\033[1;36m===== Setup the Voting Terminal... =====")
    print(f"\033[96m========================================\033[0m\n")
    voting_terminal = VotingTerminal(num_candidates, num_bits_per_vote, num_shares, threshold, prime_number, buffer_size)
    print(f"\033[0;35mVoting Terminal public-private key generated!\n")
    print(f"\033[0;35mSigning public-private key generated!\n")
    
    ######################################
    ############ Cast the votes ##########
    ######################################
    
    print(f"\033[96m==========================")
    print(f"\033[1;36m===== Cast the votes =====")
    print(f"\033[96m==========================\033[0m")
    if mode == "automatic":
        vote_cast = [random.randint(1, num_candidates) for _ in range(random.randint(num_voters // 2, num_voters))]
        vote_result = [vote_cast.count(i) for i in range(1, num_candidates + 1)]
        voter_ids = voting_terminal.get_voter_ids()
        
        for i, voter_id in enumerate(random.sample(voter_ids, len(vote_cast))):
            result = voting_terminal.cast_vote(voter_id, vote_cast[i])
            if result == "close":
                break
            
    elif mode == "manual":
        voter_ids = voting_terminal.get_voter_ids()
        print(f"\033[0;34mThe registered IDs of the voters are:")
        for voter_id in voter_ids:
            print(f"    {voter_id}")
            
        for i in range(N):
            input_id = input(f"\n\033[0mEnter your ID: ")
            input_vote = input(f"\033[0mEnter your vote: ")
            res = voting_terminal.cast_vote(str(input_id), int(input_vote))
            while res is False:
                input_id = input(f"\n\033[0mEnter your ID: ")
                input_vote = input(f"\033[0mEnter your vote: ")
                res = voting_terminal.cast_vote(str(input_id), int(input_vote))
            
    else:
        print(f"\033[91mError! the mode need to be 'automatic' or 'manual'.\033[0m")
