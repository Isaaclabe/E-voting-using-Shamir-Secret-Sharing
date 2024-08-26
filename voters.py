import uuid
from Crypto.PublicKey import ECC

class Voter:
    """
    The Voter class represents a voter in the election system.
    Each voter has a unique ID and an associated ECC key pair for secure communication and voting.
    """
    
    def __init__(self, id=None):
        """
        Initializes a Voter object with a unique ID and generates an ECC key pair.

        Args:
            id (str, optional): The ID of the voter. If not provided, a new UUID is generated.
        """
        self.id = id if id else str(uuid.uuid4())
        self.private_key, self.public_key = self.generate_keys()

    def generate_keys(self):
        """
        Generates an Elliptic Curve Cryptography (ECC) key pair for the voter.

        Returns:
            tuple: A tuple containing the private and public ECC keys.
        """
        private_key = ECC.generate(curve='P-256')
        public_key = private_key.public_key()
        return private_key, public_key
