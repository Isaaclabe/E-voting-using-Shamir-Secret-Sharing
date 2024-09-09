# E-voting-using-Shamir-Secret-Sharing

## Overview

This project implements a secure electronic voting system using cryptographic techniques to ensure the privacy, integrity, and authenticity of votes. The system leverages **Shamir's Secret Sharing Scheme** to achieve secure voting, share distribution, and vote counting.

### Key Features

- **Voter Authentication**: Voters are identified using a unique random ID and associated public-private key pair.
- **Secure Vote Casting**: Votes are encrypted and signed before being sent to external servers.
- **Shamir's Secret Sharing**: Votes are split into multiple shares, requiring a threshold number of shares to reconstruct the original vote.
- **Vote Verification and Counting**: The system ensures that votes are counted accurately and securely without revealing individual votes.

## Components

The project consists of several components, each with a specific role in the voting process:

1. **Authority Center**: The central server that initializes the election, manages voters, and aggregates final results.
2. **Voting Terminal**: The client-side application where voters cast their votes securely.
3. **External Servers**: Servers responsible for storing encrypted shares of votes and returning them upon request.
4. **Voters**: The voters registered for the election.
5. **Socket Utilities**: Functions for handling large data transfers over socket connections.

## File Structure

```
├── authority_center.py           # Authority Center server code
├── voting_terminal.py            # Voting Terminal client code
├── external_server.py            # External Server code
├── utils_server.py               # Socket utilities for sending/receiving large data
├── voter.py                      # Voter class with unique ID
├── config.sh                     # Set all the parameters of the election
├── make_authority.sh             # Run authority_center.py
├── make_terminal.sh              # Run voting_terminal.py
├── requirements.txt              # Required packages
└── README.md                     # This README file
```

## Setup

### Prerequisites

- Python 3.6 or higher
- Required Python packages:
  - `sympy` (for modular arithmetic)
  - `pycryptodome` (for cryptographic operations)
  - `tabulate` (for printing table)

You can install all the required packages using pip:

```bash
pip -r install requirements.txt
```

### Running the code

1. **Run the Authority Center**: This central server is responsible for starting external servers, handling voter authentication, and aggregating votes.

   ```bash
   chmod +x make_authority.sh
   ./make_authority.sh
   ```

Make sure to run the authority center first.

2. **Run the Voting Terminal**: This client application allows voters to cast their votes.

   ```bash
   chmod +x make_terminal.sh
   ./make_terminal.sh
   ```

### Command-Line Arguments

You can customize the election parameters in the `config.sh` file:

- **`--num_voters`**: Number of registered voters.
- **`--candidates`**: Comma-separated list of candidate names.
- **`--num_shares`**: Number of shares for secret sharing.
- **`--threshold`**: Threshold number of shares required to reconstruct the vote.
- **`--tolerance`**: Tolerance of corrupted vote.
- **`--duration`**: Duration of the election in minutes.
- **`--buffer_size`**: Buffer size for data transmission.
- **`--mode`**: Could be automatic or manual, for automatic simulation or manual casting.
- **`--N`**: Number of manual votes

