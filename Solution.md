# Summer of Bitcoin Assignment

## OBJECTIVE
The objective of this assignment is to validate the transactions in the mempool and the mine them in a block.

## APPROACH
 - Mempool Iteration and Transaction Verification:
   - Iterate through the mempool to verify transactions based on their script types.
   - Transactions with a script type of p2tr are added to the block with only basic checks, such as ensuring they have sufficient gas fees.
   - Only valid transactions are inserted into the valid mempool.
 - Gas Fee Rejection:
   - Reject transactions with gas fees less than 1500 satoshis.
 - Creation of Transaction Map:
   - Generate a map of all valid transactions containing details such as txid, transaction, wtxid, tx_weight, and fees for each transaction.
 - Wtxid Commitment:
   - Create the wtxid commitment using all the wtxids of the valid transactions, following the guidelines outlined in "Learn Me a Bitcoin."
 - Coinbase Transaction:
   - Hard-code the creation of the coinbase transaction.
 - Merkle Root Calculation:
   - Calculate the Merkle root using the txids of all valid transactions, with the txid of the coinbase transaction placed at the top.
 - Proof of Work (POW) Implementation:
   - Implement the POW algorithm by continuously increasing the nonce until a valid block header is created.
 - Creation of Valid Block Header and Output:
   - Generate the valid block header.
   - Insert the coinbase transaction and all txids into the output.txt file.


I have used Chatgpt to add comments in the codebase :)