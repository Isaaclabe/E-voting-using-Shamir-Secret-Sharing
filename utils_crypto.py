import struct
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class Encryptor:
    """
    The Encryptor class provides methods for encryption, signing data, and generating ECC keys
    used in the voting system. It handles operations required to encrypt votes and sign data securely.
    """

    def __init__(self):
        """
        Initializes the Encryptor with private and public keys for the voting terminal and for signing.
        """
        self.voting_terminal_private_key, self.voting_terminal_public_key = self.generate_keys()
        self.sign_private_key, self.sign_public_key = self.generate_keys()
       
    ###########################
    ###### Get Functions ######
    ###########################
    
    def get_signing_keys(self):
        """
        Returns the signing private and public keys.

        Returns:
            tuple: A tuple containing the signing private and public keys.
        """
        return self.sign_private_key, self.sign_public_key
        
    def get_voting_terminal_private_key(self):
        """
        Returns the voting terminal private and public keys.

        Returns:
            tuple: A tuple containing the voting terminal private and public keys.
        """
        return self.voting_terminal_private_key, self.voting_terminal_public_key
        
    ###########################
    ###### Key Functions ######
    ###########################
    
    def generate_keys(self):
        """
        Generates an ECC key pair.

        Returns:
            tuple: A tuple containing the private and public ECC keys.
        """
        private_key = ECC.generate(curve='P-256')
        public_key = private_key.public_key()
        return private_key, public_key
        
    def reconstruct_ECC_key(self, curve, point_x, point_y):
        """
        Reconstructs an ECC key from the curve and points.

        Args:
            curve (str): The curve name.
            point_x (int): The x-coordinate of the point.
            point_y (int): The y-coordinate of the point.

        Returns:
            ECC.EccKey: The reconstructed ECC key.
        """
        return ECC.construct(curve=curve, point_x=point_x, point_y=point_y)
        
    ############################
    ###### Sign Functions ######
    ############################
        
    def sign_data(self, data):
        """
        Signs the data using the signing private key.

        Args:
            data (bytes): The data to be signed.

        Returns:
            bytes: The digital signature.
        """
        hash_obj = SHA256.new(data)
        signer = DSS.new(self.sign_private_key, 'fips-186-3')
        signature = signer.sign(hash_obj)
        return signature
        
    ##################################
    ###### Encryption Functions ######
    ##################################
    
    def convert_data_to_bytes(self, data):
        """
        Converts data to bytes for encryption.

        Args:
            data: The data to be converted (tuple, int, or str).

        Returns:
            bytes: The byte representation of the data.
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
        
    def encrypt_data(self, encrypt_public_key, data):
        """
        Encrypts the data using ECC-derived AES encryption.

        Args:
            encrypt_public_key (ECC.EccKey): The public key used for encryption.
            data: The data to encrypt.

        Returns:
            tuple: A tuple containing the encrypted data and the initialization vector (IV).
        """
        data_bytes = self.convert_data_to_bytes(data)
        shared_secret_point = encrypt_public_key.pointQ * self.voting_terminal_private_key.d
        shared_secret_bytes = int(shared_secret_point.x).to_bytes(32, byteorder='big')
        aes_key = SHA256.new(shared_secret_bytes).digest()
        
        cipher = AES.new(aes_key, AES.MODE_CBC)
        iv = cipher.iv
        encrypted_data = cipher.encrypt(pad(data_bytes, AES.block_size))
        return encrypted_data, iv
        
    ############################
    ###### Main Functions ######
    ############################
    
    def encrypt_and_sign(self, encrypt_public_key, data):
        """
        Encrypts the data and signs it using the encryptor's signing key.

        Args:
            encrypt_public_key (ECC.EccKey): The public key used for encryption.
            data: The data to encrypt and sign.

        Returns:
            tuple: A tuple containing the encrypted data, IV, and signature.
        """
        encrypted_data, iv = self.encrypt_data(encrypt_public_key, data)
        signature = self.sign_data(encrypted_data)
        return encrypted_data, iv, signature


class Decryptor:
    """
    The Decryptor class provides methods for decryption, verifying signatures, and reconstructing ECC keys.
    It handles the decryption of votes and verification of voter identities.
    """
    
    def __init__(self):
        """
        Initializes the Decryptor with private and public keys for the authority center.
        """
        self.authority_center_private_key, self.authority_center_public_key = self.generate_keys()
       
    ###########################
    ###### Get Functions ######
    ###########################
    
    def get_authority_center_keys(self):
        """
        Returns the authority center's private and public keys.

        Returns:
            tuple: A tuple containing the private and public ECC keys.
        """
        return self.authority_center_private_key, self.authority_center_public_key
        
    ###########################
    ###### Key Functions ######
    ###########################
    
    def generate_keys(self):
        """
        Generates an ECC key pair.

        Returns:
            tuple: A tuple containing the private and public ECC keys.
        """
        private_key = ECC.generate(curve='P-256')
        public_key = private_key.public_key()
        return private_key, public_key
        
    def reconstruct_ECC_key(self, curve, point_x, point_y):
        """
        Reconstructs an ECC key from the curve and points.

        Args:
            curve (str): The curve name.
            point_x (int): The x-coordinate of the point.
            point_y (int): The y-coordinate of the point.

        Returns:
            ECC.EccKey: The reconstructed ECC key.
        """
        return ECC.construct(curve=curve, point_x=point_x, point_y=point_y)

    ####################################
    ###### Verification Functions ######
    ####################################
    
    def verify_signature(self, signing_public_key, data, signature):
        """
        Verifies a digital signature against the provided data and public key.

        Args:
            signing_public_key (ECC.EccKey): The public key used to verify the signature.
            data (bytes): The data that was signed.
            signature (bytes): The signature to verify.

        Returns:
            bool: True if the signature is valid, False otherwise.
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
    
    def bytes_to_tuple(self, byte_data, length=2):
        """
        Converts bytes back to a tuple of integers.

        Args:
            byte_data (bytes): The byte data to convert.
            length (int): The number of integers in the tuple.

        Returns:
            tuple: The tuple of integers.
        """
        format_string = 'q' * length
        return struct.unpack(format_string, byte_data)
        
    def bytes_to_str(self, byte_data):
        """
        Converts bytes back to a string.

        Args:
            byte_data (bytes): The byte data to convert.

        Returns:
            str: The decoded string.
        """
        return byte_data.decode('utf-8')

    def decrypt_vote(self, voting_terminal_public_key, voter_private_key, encrypted_data, iv):
        """
        Decrypts an encrypted vote using ECC-derived AES decryption.

        Args:
            voting_terminal_public_key (ECC.EccKey): The public key of the voting terminal.
            voter_private_key (ECC.EccKey): The private key of the voter.
            encrypted_data (bytes): The encrypted data to decrypt.
            iv (bytes): The initialization vector used in AES encryption.

        Returns:
            bytes: The decrypted data.
        """
        shared_secret_point = voting_terminal_public_key.pointQ * voter_private_key.d
        shared_secret_bytes = int(shared_secret_point.x).to_bytes(32, byteorder='big')
        aes_key = SHA256.new(shared_secret_bytes).digest()
        
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted_data), AES.block_size)
            
    def decrypt_and_verify_voter_id(self, voting_terminal_public_key, signing_public_key, encrypted_id, iv_id, signature_id) -> str:
        """
        Decrypts an encrypted voter ID and verifies its signature.

        Args:
            voting_terminal_public_key (ECC.EccKey): The public key of the voting terminal.
            signing_public_key (ECC.EccKey): The public key used to verify the signature.
            encrypted_id (bytes): The encrypted voter ID.
            iv_id (bytes): The initialization vector for AES encryption.
            signature_id (bytes): The signature of the encrypted voter ID.

        Returns:
            str: The decrypted voter ID if the signature is valid; otherwise, None.
        """
        decrypted_data = self.decrypt_vote(voting_terminal_public_key, self.authority_center_private_key, encrypted_id, iv_id)
        if self.verify_signature(signing_public_key, encrypted_id, signature_id):
            return self.bytes_to_str(decrypted_data)
        else:
            print("ID signature verification failed.")
            return None

    ##############################
    ###### Decode Functions ######
    ##############################
    
    def decode_vote_result(self, reconstructed_secret, total_bits, num_candidates):
        """
        Decodes the reconstructed secret to extract vote counts for each candidate.

        Args:
            reconstructed_secret (int): The reconstructed secret (combined votes).
            total_bits (int): The total number of bits used for encoding votes.
            num_candidates (int): The number of candidates.

        Returns:
            list: A list of vote counts for each candidate.
        """
        binary_string = format(reconstructed_secret, f'0{total_bits}b')
        bits_per_candidate = total_bits // num_candidates
        candidate_vote_counts = [
            int(binary_string[i:i+bits_per_candidate], 2)
            for i in range(0, total_bits, bits_per_candidate)
        ]
    
        return candidate_vote_counts
