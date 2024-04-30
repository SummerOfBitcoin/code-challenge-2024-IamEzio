use hex; // Importing hex library for hexadecimal encoding and decoding

use crate::validation_checks::op_checksig; // Importing op_checksig function from validation_checks module

use crate::{error::Result, transaction::Transaction}; // Importing Result type and Transaction struct from crate

pub fn input_verification_p2wpkh(tx_input_index: usize, tx: Transaction) -> Result<bool> {
    let witness = match tx.vin[tx_input_index].witness.clone() { // Extracting witness data from transaction input
        Some(value) => value, // If witness exists, assign it to witness variable
        None => Vec::new(), // If witness does not exist, create an empty vector
    };

    Ok(script_execution_p2wpkh(witness, tx, tx_input_index)?) // Calling script_execution_p2wpkh function with witness data
}

fn script_execution_p2wpkh(
    witness: Vec<String>, // Witness data containing signature and public key
    tx: Transaction,
    tx_input_index: usize,
) -> Result<bool> {
    if witness.len() == 0 { // Checking if witness is empty
        return Ok(false); // Returning false if witness is empty
    }

    if tx.vin[tx_input_index].scriptsig.clone().unwrap().len() != 0 { // Checking if scriptsig is not empty
        return Ok(false); // Returning false if scriptsig is not empty
    }

    let input_type = "P2WPKH"; // Setting input type as P2WPKH

    let mut stack = Vec::new(); // Initializing stack for script execution

    // PUSHING COMPONENTS OF THE WITNESS IN THE STACK := SIGNATURE AND PUBLIC KEY
    stack.push(hex::decode(&witness[0])?); // Decoding and pushing signature to the stack
    stack.push(hex::decode(&witness[1])?); // Decoding and pushing public key to the stack

    // OP_CHECKSIG
    let script_result = op_checksig(&mut stack, tx.clone(), tx_input_index, input_type)?; // Calling op_checksig function

    Ok(script_result) // Returning script execution result
}

// TO TEST MY CODE DURING DEVELOPMENT
#[cfg(test)]
mod test {
    use std::fs;

    use walkdir::WalkDir;

    use super::*;

    #[test]
    fn test_script_execution_p2wpkh() -> Result<()> {
        // let mut s_count = 0;
        // let mut f_count = 0;
        let mempool_dir = "./mempool"; // Path to mempool directory
        for entry in WalkDir::new(mempool_dir).into_iter().filter_map(|e| e.ok()) { // Iterating over mempool directory
            let path = entry.path(); // Getting path of current file
            if path.is_file() { // Checking if it's a file
                match fs::read_to_string(path) { // Reading file contents
                    Ok(contents) => {
                        match serde_json::from_str::<Transaction>(&contents) { // Parsing JSON into Transaction struct
                            Ok(transaction) => {
                                let all_p2sh = transaction.vin.iter().all(|input| { // Checking if all inputs are of type v0_p2wpkh
                                    input.prevout.scriptpubkey_type == "v0_p2wpkh".to_string()
                                });
                                if all_p2sh { // Proceeding if all inputs are of type v0_p2wpkh
                                    let result = script_execution_p2wpkh( // Calling script_execution_p2wpkh function
                                        transaction.vin[0].witness.clone().unwrap(),
                                        transaction,
                                        0,
                                    )?;

                                    if result == true { // Handling script execution result
                                    } else {
                                    }

                                }
                            }
                            Err(_e) => {
                            }
                        }
                    }
                    Err(_e) => {}
                }
            }
        }
        Ok(()) // Returning Ok result
    }

    #[test]
    fn test2() -> Result<()> {
        let path =
            "./mempool/0a5d6ddc87a9246297c1038d873eec419f04301197d67b9854fa2679dbe3bd65.json";

        // Read the JSON file
        let data = fs::read_to_string(path).expect("Unable to read file");

        // Deserialize JSON into Rust data structures
        let transaction: Transaction = serde_json::from_str(&data)?;

        let tx = transaction.clone();
        let result = script_execution_p2wpkh(tx.vin[0].witness.clone().unwrap(), tx, 0)?;

        println!("{}", result);

        Ok(())
    }
}
