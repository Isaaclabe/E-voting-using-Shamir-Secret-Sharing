# E-voting-using-Shamir-Secret-Sharing

## Overview

This project implements a secure electronic voting system using cryptographic techniques to ensure the privacy, integrity, and authenticity of votes. The system leverages **Shamir's Secret Sharing Scheme**, **Elliptic Curve Cryptography (ECC)**, and **AES Encryption** to achieve secure voting, share distribution, and vote counting.

### Key Features

- **Voter Authentication**: Voters are identified using a unique ID and associated public-private key pair.
- **Secure Vote Casting**: Votes are encrypted and signed before being sent to external servers.
- **Shamir's Secret Sharing**: Votes are split into multiple shares, requiring a threshold number of shares to reconstruct the original vote.
- **Vote Verification and Counting**: The system ensures that votes are counted accurately and securely without revealing individual votes.

## Components

The project consists of several components, each with a specific role in the voting process:

1. **Authority Center**: The central server that initializes the election, manages voters, and aggregates final results.
2. **Voting Terminal**: The client-side application where voters cast their votes securely.
3. **External Servers**: Servers responsible for storing encrypted shares of votes and returning them upon request.
4. **Cryptographic Utilities**: Utility functions and classes to handle encryption, decryption, signing, and verification.
5. **Shamir's Secret Sharing Utilities**: Functions for generating and reconstructing shares using Shamir's Secret Sharing scheme.
6. **Socket Utilities**: Functions for handling large data transfers over socket connections.

## File Structure

```
├── authority_center.py           # Authority Center server code
├── voting_terminal.py            # Voting Terminal client code
├── external_server.py            # External Server code
├── utils_crypto.py               # Cryptographic utilities for encryption, decryption, signing
├── utils_shamir.py               # Shamir's Secret Sharing functions
├── utils_server.py               # Socket utilities for sending/receiving large data
├── voter.py                      # Voter class with unique ID and ECC key pair generation
└── README.md                     # This README file
```

## Setup

### Prerequisites

- Python 3.6 or higher
- Required Python packages:
  - `sympy` (for modular arithmetic)
  - `pycryptodome` (for cryptographic operations)

You can install the required packages using pip:

```bash
pip install sympy pycryptodome
```

### Running the Servers and Client

1. **Start External Servers**: These servers store encrypted shares of votes.
   
   ```bash
   python external_server.py
   ```

   Repeat this step for each external server on different ports.

2. **Start the Authority Center**: The central server that manages voter authentication and aggregates the votes.

   ```bash
   python authority_center.py
   ```

3. **Run the Voting Terminal**: This client application allows voters to cast their votes.

   ```bash
   python voting_terminal.py
   ```

### Command-Line Arguments

You can customize the election parameters by using command-line arguments when starting the Authority Center and Voting Terminal:

- **`--num_voters`**: Number of registered voters.
- **`--candidates`**: Comma-separated list of candidate names.
- **`--num_shares`**: Number of shares for secret sharing.
- **`--threshold`**: Threshold number of shares required to reconstruct the vote.
- **`--duration`**: Duration of the election in minutes.
- **`--buffer_size`**: Buffer size for data transmission.

Example:

```bash
python authority_center.py --num_voters 10 --candidates Alice,Bob,Charlie --num_shares 4 --threshold 3 --duration 1
```

## How It Works

1. **Initialization**: The Authority Center initializes voters and generates public-private key pairs for each voter. It also starts external servers to store vote shares.
   
2. **Vote Casting**: The Voting Terminal authenticates the voter and securely receives the vote. The vote is then encrypted, signed, and split into shares using Shamir's Secret Sharing scheme. These shares are distributed to external servers.

3. **Vote Collection and Counting**: After the voting period ends, the Authority Center retrieves the shares from external servers, verifies them, and reconstructs the votes using Lagrange interpolation.

4. **Result Announcement**: The final results are displayed, showing the vote count for each candidate.

## Security Features

- **Encryption**: Votes are encrypted using ECC and AES to ensure privacy.
- **Digital Signatures**: Votes are signed to ensure authenticity and prevent tampering.
- **Shamir's Secret Sharing**: The use of secret sharing ensures that no single server can reconstruct the vote, providing robustness against compromised servers.
- **Verification**: The system verifies the integrity of the votes before counting, ensuring only valid votes are included.

## Contributions

Contributions to improve this project are welcome! Please fork the repository and create a pull request with your changes.

## License

This project is open-source and available under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Acknowledgments

- **Python Cryptography Toolkit (pycryptodome)**: Provides cryptographic modules for secure operations.
- **SymPy**: A Python library for symbolic mathematics, used for modular arithmetic operations.
- **Shamir's Secret Sharing**: A cryptographic algorithm for secure multi-party computation.



### Conclusion

This `README.md` file provides a comprehensive overview of your project, guiding users through setup, usage, and understanding the system's functionality and security features. It also outlines the project's file structure and provides command-line options for flexibility.
