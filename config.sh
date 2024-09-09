#######################################################
#######################################################
### Configuration constants for the e-voting system ###
#######################################################
#######################################################

# Number of voters in the election
NUM_VOTERS=10

# List of candidates in the election (comma-separated)
CANDIDATES="Alice,Bob,Charles,David"

# Number of shares for secret sharing
NUM_SHARES=10

# Threshold for secret reconstruction
THRESHOLD=7

# Tolerance of corrupted vote
TOLERANCE=0.2

# Duration of the election in minutes
ELECTION_DURATION=0.5

# Buffer size for data transmission
BUFFER_SIZE=$((16384 * 4))

# Mode for the voting terminal
MODE="automatic"

# Number of manual votes
N=2
