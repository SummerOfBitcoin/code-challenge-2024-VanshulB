# Solving the Summer of Bitcoin 2024 Challenge

To tackle the Summer of Bitcoin 2024 challenge, I designed a block construction program that sticks to Bitcoin's fundamental principles.<br> Here's how I approached it:

<br>

## Transaction Validation

I started by parsing transactions from JSON files and checking their structure and content. I also made sure to serialize transactions correctly based on the input address type.

<br>

## Address Validation

Next, I integrated address validation into the transaction validation process. This involved appending the sighash_type to the trimmed transaction byte sequence, double hashing the result, and verifying the message against the public key and signature.

<br>

## Block Header Creation

I defined the block header structure, including version, previous block hash, Merkle root, timestamp, bits, and nonce. I then serialized the block headers into bytes for hashing and Proof of Work (PoW) calculation.

<br>

## Merkle Tree Construction

I organized transactions into a Merkle tree to compute the Merkle root. The Merkle root hash was then included in the block header.

<br>

## Proof of Work (PoW) Algorithm

I implemented the PoW algorithm to find a hash value below the target difficulty. I incremented the block header nonces until I found a suitable hash.

<br>

## Implementation Details

### Here's a step-by-step breakdown of the implementation:

- Transaction Parsing and Serialization: I parsed transactions from JSON files and validated their  structure and content. I also serialized transactions correctly based on the input address type.

- Message Signing and Verification: I appended the sighash_type to the trimmed transaction byte sequence, double hashed the result, and verified the message against the public key and signature using Secp256k1 libraries.

- Address Validation: I verified the signature against the public key to ensure that only transactions from legitimate addresses were included in the block.

- Block Mining: I ranked transactions by fees per weight and efficiently utilized the block space to maximize collected fees. I also initialized coinbase transactions with appropriate rewards and witness commitments.

- Output Generation: The final output file, "output.txt," contained the serialized block header, coinbase transaction, and mined transaction IDs.

<br>

## Results and Performance

The solution successfully mined blocks by including valid transactions from the mempool folder. Address validation ensured that only transactions from legitimate addresses were included in the block, enhancing security and trust. The PoW algorithm efficiently computed valid block hashes below the target difficulty.
I was able to get a score of 96 out of 100.
