import uuid
from Crypto.PublicKey import ECC

class Voter:
    """
    The Voter class represents a voter in the election system.
    Each voter has a unique ID.
    """
    
    def __init__(self, id=None):
        """
        Initializes a Voter object with a unique ID.

        Args:
            id (str, optional): The ID of the voter. If not provided, a new UUID is generated.
        """
        self.id = id if id else str(uuid.uuid4())
