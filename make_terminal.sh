#!/bin/bash

# Load the configuration from config.py
source config.sh

# Run the voting_terminal.py script with the parameters from config.py
python3 voting_terminal.py \
    --num_voters "$NUM_VOTERS" \
    --candidates "$CANDIDATES" \
    --num_shares "$NUM_SHARES" \
    --threshold "$THRESHOLD" \
    --mode "$MODE" \
    --N "$N" \
    --buffer_size "$BUFFER_SIZE"
