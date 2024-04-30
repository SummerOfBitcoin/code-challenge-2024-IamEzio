use crate::error::Result; // Importing the Result type from the error module

use crate::transaction::Transaction; // Importing the Transaction struct
use super::serialise_tx::double_sha256; // Importing the double_sha256 function

// Returns the Merkel root, coinbase transaction, coinbase transaction ID, and transaction IDs to be included in the block
pub fn generate_roots(map: Vec<(String, Transaction, String, usize, u64)>) -> Result<(String, String, String, Vec<String>)> {
    let tx_weight_limit = 3993000; // Define the transaction weight limit
    let mut current_tx_weight = 0; // Initialize the current transaction weight
    let mut txids: Vec<String> = Vec::new(); // Initialize a vector to store transaction IDs
    let mut wtxids: Vec<String> = Vec::new(); // Initialize a vector to store witness transaction IDs
    let mut block_subsidy = 0; // Initialize the block subsidy

    wtxids.push("0000000000000000000000000000000000000000000000000000000000000000".to_string()); // Push a default value to the witness transaction IDs vector

    for (txid, _, wtxid, weight, fees) in map { // Iterate over the input map
        if current_tx_weight >= tx_weight_limit { // Check if the current transaction weight exceeds the limit
            break; // Exit the loop
        }
        current_tx_weight += weight; // Update the current transaction weight
        block_subsidy += fees; // Update the block subsidy

        txids.push(txid); // Push the transaction ID to the transaction IDs vector
        wtxids.push(wtxid); // Push the witness transaction ID to the witness transaction IDs vector
    }

    let witness_root_hash = merkel_root(wtxids)?; // Calculate the witness root hash

    let (coinbase_tx, txid_coinbase_tx) = create_coinbase(witness_root_hash, block_subsidy)?; // Create the coinbase transaction and coinbase transaction ID

    let mut coinbase_txid_bytes = double_sha256(&hex::decode(&txid_coinbase_tx)?); // Calculate the double SHA-256 hash of the coinbase transaction ID
    coinbase_txid_bytes.reverse(); // Reverse the bytes

    let coinbase_txid = hex::encode(coinbase_txid_bytes); // Encode the coinbase transaction ID as hexadecimal

    txids.insert(0, coinbase_txid.clone()); // Insert the coinbase transaction ID at the beginning of the transaction IDs vector

    let merkel_root = merkel_root(txids.clone())?; // Calculate the Merkle root

    Ok((merkel_root, coinbase_tx, coinbase_txid, txids)) // Return the result tuple
}

// Function to calculate the Merkle root for a vector of transaction IDs
fn merkel_root(txids: Vec<String>) -> Result<String> {
    let mut txids_natural: Vec<String> = Vec::new(); // Initialize a vector to store the natural order transaction IDs

    for txid in txids.iter() { // Iterate over the input transaction IDs
        let mut txid_bytes = hex::decode(txid)?; // Decode the hexadecimal transaction ID to bytes
        txid_bytes.reverse(); // Reverse the bytes

        txids_natural.push(hex::encode(txid_bytes)); // Encode the bytes as hexadecimal and push to the natural order transaction IDs vector
    }

    while txids_natural.len() > 1 { // Iterate until only one transaction ID remains
        let mut next_level = Vec::new(); // Initialize a vector to store the next level of Merkle tree nodes

        // If odd number of transaction IDs, duplicate the last one
        if txids_natural.len() % 2 != 0 { // Check if the number of transaction IDs is odd
            txids_natural.push(txids_natural.last().unwrap().clone()); // Duplicate the last transaction ID
        }

        for chunk in txids_natural.chunks(2) { // Iterate over pairs of transaction IDs
            match chunk {
                [one, two] => { // If there are two transaction IDs in the chunk
                    let concat = one.to_owned() + two; // Concatenate the transaction IDs
                    next_level.push(hex::encode(double_sha256(&hex::decode(&concat)?))); // Calculate the double SHA-256 hash of the concatenated transaction IDs and push to the next level vector
                }
                _ => unreachable!(), // This case should never happen due to the duplication logic above
            }
        }

        txids_natural = next_level; // Update the transaction IDs to the next level
    }

    Ok(txids_natural[0].clone()) // Return the Merkle root
}

// Create the coinbase transaction and coinbase transaction ID
pub fn create_coinbase(witness_root_hash: String, block_subsidy: u64) -> Result<(String, String)> {
    let mut coinbase_tx = String::new(); // Initialize a string to store the coinbase transaction
    let mut txid_coinbase_tx = String::new(); // Initialize a string to store the coinbase transaction ID

    let block_amount = 650082296 + block_subsidy; // Calculate the block amount

    let witness_reserved_value = "0000000000000000000000000000000000000000000000000000000000000000".to_string(); // Define the witness reserved value
    let witness_commit = format!("{}{}", witness_root_hash, witness_reserved_value); // Concatenate the witness root hash and witness reserved value

    let wtxid_commit = hex::encode(double_sha256(&hex::decode(&witness_commit)?)); // Calculate the double SHA-256 hash of the witness commitment

    let wtxid_commitment = format!("{}{}", "6a24aa21a9ed", wtxid_commit); // Format the witness transaction ID commitment

    // VERSION MARKER FLAG
    coinbase_tx.push_str("01000000"); // Append the version marker flag to the coinbase transaction
    txid_coinbase_tx.push_str("01000000"); // Append the version marker flag to the coinbase transaction ID

    coinbase_tx.push_str("0001"); // Append the version number to the coinbase transaction

    // INPUT COUNT
    coinbase_tx.push_str("01"); // Append the input count to the coinbase transaction
    txid_coinbase_tx.push_str("01"); // Append the input count to the coinbase transaction ID

    // INPUT
    coinbase_tx.push_str("0000000000000000000000000000000000000000000000000000000000000000"); // Append the coinbase input to the coinbase transaction
    coinbase_tx.push_str("ffffffff"); // Append the sequence number to the coinbase transaction
    coinbase_tx.push_str("25"); // Append the script length to the coinbase transaction
    coinbase_tx.push_str("03a0bb0d184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100"); // Append the coinbase script to the coinbase transaction
    coinbase_tx.push_str("ffffffff"); // Append the output marker to the coinbase transaction

    // OUTPUT COUNT
    coinbase_tx.push_str("02"); // Append the output count to the coinbase transaction

    // OUTPUT
    coinbase_tx.push_str(&hex::encode(block_amount.to_le_bytes())); // Append the block amount to the coinbase transaction
    coinbase_tx.push_str("19"); // Append the script length to the coinbase transaction
    coinbase_tx.push_str("76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac"); // Append the coinbase script to the coinbase transaction

    coinbase_tx.push_str("0000000000000000"); // Append the lock time to the coinbase transaction
    coinbase_tx.push_str("26"); // Append the witness commitment marker to the coinbase transaction
    coinbase_tx.push_str(&wtxid_commitment); // Append the witness commitment to the coinbase transaction

    // ------------------TXID--------------------------

    // INPUT
    txid_coinbase_tx.push_str("0000000000000000000000000000000000000000000000000000000000000000"); // Append the coinbase input to the coinbase transaction ID
    txid_coinbase_tx.push_str("ffffffff"); // Append the sequence number to the coinbase transaction ID
    txid_coinbase_tx.push_str("25"); // Append the script length to the coinbase transaction ID
    txid_coinbase_tx.push_str("03a0bb0d184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100"); // Append the coinbase script to the coinbase transaction ID
    txid_coinbase_tx.push_str("ffffffff"); // Append the output marker to the coinbase transaction ID

    // OUTPUT COUNT
    txid_coinbase_tx.push_str("02"); // Append the output count to the coinbase transaction ID

    // OUTPUT
    txid_coinbase_tx.push_str(&hex::encode(block_amount.to_le_bytes())); // Append the block amount to the coinbase transaction ID
    txid_coinbase_tx.push_str("19"); // Append the script length to the coinbase transaction ID
    txid_coinbase_tx.push_str("76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac"); // Append the coinbase script to the coinbase transaction ID

    txid_coinbase_tx.push_str("0000000000000000"); // Append the lock time to the coinbase transaction ID
    txid_coinbase_tx.push_str("26"); // Append the witness commitment marker to the coinbase transaction ID
    txid_coinbase_tx.push_str(&wtxid_commitment); // Append the witness commitment to the coinbase transaction ID

    // -----------------TXID----------------------------

    // WITNESS
    coinbase_tx.push_str("01"); // Append the witness marker to the coinbase transaction
    coinbase_tx.push_str("20"); // Append the witness length to the coinbase transaction
    coinbase_tx.push_str("0000000000000000000000000000000000000000000000000000000000000000"); // Append the witness data to the coinbase transaction

    coinbase_tx.push_str("00000000"); // Append the sequence number to the coinbase transaction
    txid_coinbase_tx.push_str("00000000"); // Append the sequence number to the coinbase transaction ID

    Ok((coinbase_tx, txid_coinbase_tx)) // Return the coinbase transaction and coinbase transaction ID
}

// Test module
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn merkel_test() -> Result<()> {
        let txids = vec![
            "2ec4532bbb79b5875f3e86cf11f3f1e42b74717c573368a92558cff7b1033365".to_string(),
            "958ffdb52a9148d3a6fca79d21d6b17e146c94909f6e63dd7723e409b10a1cd2".to_string(),
            "dbba5fdfee9cb36e4f80db9ed7daebaa1460f9836bb0328db2f9f2dc4cd02d14".to_string(),
        ]; // Define sample transaction IDs

        let merkel_root = merkel_root(txids)?; // Calculate the Merkle root

        println!("{}", merkel_root); // Print the Merkle root

        Ok(()) // Return Ok indicating success
    }
}
