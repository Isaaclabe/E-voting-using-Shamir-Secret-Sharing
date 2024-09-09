#!/bin/bash

# Load the configuration from config.py
source config.sh

# Run the authority_center.py script with the parameters from config.py
python3 authority_center.py \
    --num_voters "$NUM_VOTERS" \
    --candidates "$CANDIDATES" \
    --num_shares "$NUM_SHARES" \
    --threshold "$THRESHOLD" \
    --tolerance "$TOLERANCE" \
    --duration "$ELECTION_DURATION" \
    --buffer_size "$BUFFER_SIZE"
