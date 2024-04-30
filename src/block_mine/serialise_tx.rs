use std::fs; // Importing the file system module
use sha2::{Digest, Sha256}; // Importing functions for SHA-256 hashing
use walkdir::WalkDir; // Importing WalkDir for directory traversal

use crate::{error::Result, transaction::Transaction}; // Importing Result type and Transaction struct from the crate

pub fn double_sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(&Sha256::digest(data)).to_vec() // Perform double SHA-256 hashing on input data
}

// Iterate through the valid-mempool to create a vector of features to be used for each transaction in block mining
pub fn create_txid_tx_map() -> Result<Vec<(String, Transaction, String, usize, u64)>> {

    let v_mempool_dir = "./valid-mempool"; // Define the directory for valid mempool
    let mut map: Vec<(String, Transaction, String, usize, u64)> = Vec::new(); // Initialize a vector to store transaction features

    for entry in WalkDir::new(v_mempool_dir) // Iterate over entries in the directory
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path(); // Get the path of the entry
        if path.is_file() { // Check if the entry is a file
            match fs::read_to_string(path) { // Read contents of the file
                Ok(contents) => match serde_json::from_str::<Transaction>(&contents) { // Deserialize JSON contents into Transaction struct
                    Ok(transaction) => {
                        let (result, serialised_tx, serialised_wtx, tx_weight, fees) =
                            serialise_tx(&transaction)?; // Serialize transaction

                        if result == true { // If serialization is successful
                            let mut txid = double_sha256(&serialised_tx); // Calculate transaction ID
                            let mut wtxid = double_sha256(&serialised_wtx); // Calculate witness transaction ID

                            txid.reverse(); // Reverse transaction ID bytes
                            wtxid.reverse(); // Reverse witness transaction ID bytes

                            let txid = hex::encode(txid); // Encode transaction ID as hexadecimal
                            let wtxid = hex::encode(wtxid); // Encode witness transaction ID as hexadecimal

                            // Find the correct position to insert the transaction based on its fees
                            let position = map
                                .iter()
                                .position(|(_, _, _, net_weight, gas_fees)| {
                                    fees / tx_weight as u64 > *gas_fees / (*net_weight as u64)
                                })
                                .unwrap_or(map.len());
                            map.insert(position, (txid, transaction, wtxid, tx_weight, fees)); // Insert transaction features into the map
                        }
                    }
                    Err(_e) => {}
                },
                Err(_e) => {}
            }
        }
    }

    Ok(map) // Return the transaction ID - transaction map
}

// Aims to create the raw transaction for transaction ID and raw witness transaction for witness transaction ID
fn serialise_tx(tx: &Transaction) -> Result<(bool, Vec<u8>, Vec<u8>, usize, u64)> {
    let tx_type;
    if tx.vin[0].witness == None {
        tx_type = "LEGACY"; // Set transaction type to legacy if witness field is None
    } else {
        tx_type = "SEGWIT"; // Set transaction type to SegWit otherwise
    }

    let mut fees = 0; // Initialize fees variable
    let mut non_witness_bytes = 0; // Initialize non-witness bytes variable
    let mut witness_bytes = 0; // Initialize witness bytes variable

    // Calculate gas fees
    for input in tx.vin.iter() {
        fees += input.prevout.value; // Add input values to fees
    }

    for output in tx.vout.iter() {
        fees -= output.value; // Subtract output values from fees
    }

    let mut raw_tx: Vec<u8> = Vec::new(); // Initialize raw transaction vector
    let mut raw_wtx: Vec<u8> = Vec::new(); // Initialize raw witness transaction vector

    if tx_type == "LEGACY" {
        // VERSION
        raw_tx.extend(tx.version.to_le_bytes()); // Append version to raw transaction
        non_witness_bytes += 4; // Increment non-witness bytes count

        // INPUT COUNT
        if tx.vin.len() >= 50 {
            return Ok((false, Vec::new(), Vec::new(), 0, 0)); // Return if input count exceeds limit
        }

        raw_tx.push(tx.vin.len().try_into()?); // Append input count to raw transaction
        non_witness_bytes += 1; // Increment non-witness bytes count

        // INPUTS
        for input in tx.vin.iter() {
            // TXID REVERSED
            let mut txid = hex::decode(&input.txid.clone())?; // Decode and reverse transaction ID
            txid.reverse();
            // SCRIPT SIG
            let script_sig = hex::decode(&input.scriptsig.clone().unwrap())?; // Decode script signature
            let script_sig_len = script_sig.len(); // Get script signature length

            // Append transaction ID, output index, script signature length, and script signature to raw transaction
            raw_tx.extend_from_slice(&txid);
            raw_tx.extend(input.vout.to_le_bytes());
            raw_tx.push(script_sig.len().try_into()?);
            raw_tx.extend_from_slice(&script_sig);
            raw_tx.extend(input.sequence.to_le_bytes());

            non_witness_bytes += 32 + 4 + 1 + script_sig_len + 4; // Update non-witness bytes count
        }

        // OUTPUT COUNT
        if tx.vout.len() >= 200 {
            return Ok((false, Vec::new(), Vec::new(), 0, 0)); // Return if output count exceeds limit
        }

        raw_tx.push(tx.vout.len().try_into()?); // Append output count to raw transaction
        non_witness_bytes += 1; // Increment non-witness bytes count

        // OUTPUTS
        for output in tx.vout.iter() {
            // SCRIPT PUB KEY
            let scriptpubkey = hex::decode(&output.scriptpubkey.clone())?; // Decode script public key
            let scriptpubkey_len = scriptpubkey.len(); // Get script public key length

            // Append output value and script public key length to raw transaction
            raw_tx.extend(output.value.to_le_bytes());
            raw_tx.push(scriptpubkey.len().try_into()?);
            raw_tx.extend_from_slice(&scriptpubkey);

            non_witness_bytes += 8 + 1 + scriptpubkey_len; // Update non-witness bytes count
        }

        // LOCKTIME
        raw_tx.extend(tx.locktime.to_le_bytes()); // Append locktime to raw transaction
        non_witness_bytes += 4; // Increment non-witness bytes count

        raw_wtx = raw_tx.clone(); // Set raw witness transaction to raw transaction
    } else {
        // VERSION
        raw_tx.extend(tx.version.to_le_bytes()); // Append version to raw transaction
        raw_wtx.extend(tx.version.to_le_bytes()); // Append version to raw witness transaction

        non_witness_bytes += 4; // Increment non-witness bytes count

        // MARKER FLAG IN WTX ONLY
        let marker = 00;
        let flag = 01;
        raw_wtx.push(marker.try_into()?);
        raw_wtx.push(flag.try_into()?);

        witness_bytes += 1 + 1; // Increment witness bytes count

        // INPUT COUNT
        if tx.vin.len() >= 200 {
            return Ok((false, Vec::new(), Vec::new(), 0, 0)); // Return if input count exceeds limit
        }
        raw_tx.push(tx.vin.len().try_into()?); // Append input count to raw transaction
        raw_wtx.push(tx.vin.len().try_into()?); // Append input count to raw witness transaction

        non_witness_bytes += 1; // Increment non-witness bytes count

        // INPUTS
        for input in tx.vin.iter() {
            // TXID REVERSED
            let mut txid = hex::decode(&input.txid.clone())?; // Decode and reverse transaction ID
            txid.reverse();

            // SCRIPT SIG
            let script_sig = hex::decode(&input.scriptsig.clone().unwrap())?; // Decode script signature
            let script_sig_len = script_sig.len(); // Get script signature length

            // Append transaction ID and output index to raw transaction
            raw_tx.extend_from_slice(&txid);
            raw_tx.extend(input.vout.to_le_bytes());

            // Append transaction ID and output index to raw witness transaction
            raw_wtx.extend_from_slice(&txid);
            raw_wtx.extend(input.vout.to_le_bytes());

            non_witness_bytes += 32 + 4; // Update non-witness bytes count

            if script_sig.len() >= 255 {
                return Ok((false, Vec::new(), Vec::new(), 0, 0)); // Return if script signature length exceeds limit
            }

            // Append script signature length and script signature to raw transaction and raw witness transaction
            raw_tx.push(script_sig.len().try_into()?);
            raw_wtx.push(script_sig.len().try_into()?);

            non_witness_bytes += 1; // Update non-witness bytes count

            if script_sig.len() != 0 {
                raw_tx.extend_from_slice(&script_sig);
                raw_wtx.extend_from_slice(&script_sig);

                non_witness_bytes += script_sig_len; // Update non-witness bytes count
            }
            raw_tx.extend(input.sequence.to_le_bytes());
            raw_wtx.extend(input.sequence.to_le_bytes());

            non_witness_bytes += 4; // Update non-witness bytes count
        }

        // OUTPUT COUNT
        if tx.vout.len() >= 255 {
            return Ok((false, Vec::new(), Vec::new(), 0, 0)); // Return if output count exceeds limit
        }
        raw_tx.push(tx.vout.len().try_into()?); // Append output count to raw transaction
        raw_wtx.push(tx.vout.len().try_into()?); // Append output count to raw witness transaction

        non_witness_bytes += 1; // Increment non-witness bytes count

        // OUTPUTS
        for output in tx.vout.iter() {
            // SCRIPT PUB KEY
            let scriptpubkey = hex::decode(&output.scriptpubkey.clone())?; // Decode script public key
            let scriptpubkey_len = scriptpubkey.len(); // Get script public key length

            // Append output value to raw transaction and raw witness transaction
            raw_tx.extend(output.value.to_le_bytes());
            raw_wtx.extend(output.value.to_le_bytes());

            non_witness_bytes += 8; // Update non-witness bytes count

            if scriptpubkey.len() >= 50 {
                return Ok((false, Vec::new(), Vec::new(), 0, 0)); // Return if script public key length exceeds limit
            }
            // Append script public key length and script public key to raw transaction and raw witness transaction
            raw_tx.push(scriptpubkey.len().try_into()?);
            raw_wtx.push(scriptpubkey.len().try_into()?);
            raw_tx.extend_from_slice(&scriptpubkey);
            raw_wtx.extend_from_slice(&scriptpubkey);

            non_witness_bytes += 1 + scriptpubkey_len; // Update non-witness bytes count
        }

        // Witness only in WTX
        for input in tx.vin.iter() {
            let witness = input.witness.clone().unwrap(); // Clone witness
            // let witness_len = witness.len();

            raw_wtx.push(witness.len().try_into()?); // Append witness length to raw witness transaction

            witness_bytes += 1; // Increment witness bytes count

            for item in witness {
                let item_bytes = hex::decode(&item)?; // Decode item
                let item_bytes_len = item_bytes.len(); // Get item length
                raw_wtx.push(item_bytes.len().try_into()?); // Append item length to raw witness transaction
                raw_wtx.extend_from_slice(&item_bytes); // Append item to raw witness transaction

                witness_bytes += 1 + item_bytes_len; // Update witness bytes count
            }
        }

        // LOCKTIME
        raw_tx.extend(tx.locktime.to_le_bytes()); // Append locktime to raw transaction
        raw_wtx.extend(tx.locktime.to_le_bytes()); // Append locktime to raw witness transaction

        non_witness_bytes += 4; // Increment non-witness bytes count
    }

    let tx_weight = (non_witness_bytes * 4) + (witness_bytes); // Calculate transaction weight

    Ok((true, raw_tx, raw_wtx, tx_weight, fees)) // Return serialized transaction data
}

// Test module
#[cfg(test)]
mod test {
    use std::fs; // Import file system module

    use super::*;

    #[test]
    fn test2() -> Result<()> {
        let path =
            "./mempool/fcc4d2ad88b7a040dc98ae29946b794258ae7c8ba1a4300a6fc761d0c9cb6a1f.json"; // Define file path

        let data = fs::read_to_string(path).expect("Unable to read file"); // Read file contents as string

        let transaction: Transaction = serde_json::from_str(&data)?; // Deserialize JSON data into Transaction struct

        let (_, tx, wtx, _, _) = serialise_tx(&transaction)?; // Serialize transaction

        println!("{}", hex::encode(tx)); // Print hexadecimal encoding of raw transaction
        println!("{}", hex::encode(wtx)); // Print hexadecimal encoding of raw witness transaction

        Ok(()) // Return Ok indicating success
    }

}
