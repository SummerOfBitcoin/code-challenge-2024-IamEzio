// OPERATE ON THE P2PKH TRANSACTIONS 
use hex; // Importing hex library for hexadecimal encoding and decoding
use ripemd::Ripemd160; // Importing Ripemd160 hashing algorithm
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1}; // Importing secp256k1 library for ECDSA operations
use sha2::{Digest, Sha256}; // Importing Sha256 hashing algorithm

use crate::error::Result; // Importing custom Result type
use crate::transaction::Transaction; // Importing custom Transaction type

pub fn input_verification_p2pkh(tx: Transaction, tx_input_index: usize) -> Result<bool> {
    // EXTRACT THE SCRIPT PUB KEY ASM AND SCRIPT-SIG ASM FROM THE INPUT

    let scriptsig_asm = match tx.vin[tx_input_index].scriptsig_asm.clone() {
        Some(value) => value, // If scriptsig_asm exists, assign it to scriptsig_asm variable
        None => {
            return Ok(false); // If scriptsig_asm does not exist, return false
        }
    };

    let scriptpubkey_asm = tx.vin[tx_input_index].prevout.scriptpubkey_asm.clone(); // Extracting scriptpubkey_asm

    Ok(script_execution( // Calling script_execution function with extracted data
        scriptpubkey_asm,
        scriptsig_asm,
        tx,
        tx_input_index,
    ))
}

// EXECUTE THE SCRIPT SIG ASM
fn script_execution(
    scriptpubkey_asm: String,
    scriptsig_asm: String,
    tx: Transaction,
    tx_input_index: usize,
) -> bool {
    let sigscript_asm_slices: Vec<&str> = scriptsig_asm.split_whitespace().collect(); // Splitting scriptsig_asm into slices

    let signature = *sigscript_asm_slices.get(1).expect("Signature missing"); // Extracting signature
    let pubkey = *sigscript_asm_slices.get(3).expect("Public key missing"); // Extracting public key

    let sig = hex::decode(signature).expect("Failed to decode signature"); // Decoding signature from hexadecimal
    let pubkey = hex::decode(pubkey).expect("Failed to decode public key"); // Decoding public key from hexadecimal

    let mut stack: Vec<Vec<u8>> = Vec::new(); // Initializing stack for script execution

    // PUSH THE SIGNATURE AND PUBLIC IN THE STACK

    stack.push(sig); // Pushing signature to the stack
    stack.push(pubkey); // Pushing public key to the stack

    let op_codes: Vec<&str> = scriptpubkey_asm.split_whitespace().collect(); // Splitting scriptpubkey_asm into opcodes

    // LOGIC IMPLEMENTATION OF THE OPCODES THAT COME IN THE PATH 
    for op_code in op_codes.iter() { // Iterating over opcodes
        match *op_code { // Matching opcode
            "OP_DUP" => {
                let top = stack.last().cloned().expect("STACK UNDEFLOW: OP_DUP"); // Duplicating top element of stack
                stack.push(top); // Pushing duplicated element to the stack
            }
            "OP_HASH160" => {
                let top = stack.pop().expect("STACK UNDERFLOW: OP_HASH160"); // Popping top element from the stack
                let hash = hash160(&top); // Computing RIPEMD160 hash of the popped element
                stack.push(hash); // Pushing hash to the stack
            }
            "OP_PUSHBYTES_20" => {
                // The next iteration will have the actual bytes to push
                continue; // Skipping this iteration
            }
            _ => {
                // Assuming the curernt op_code is the bytes pushed by OP_PUSHBYTES_20
                if op_code.len() == 40 { // Checking if the opcode length is 40 (indicating hexadecimal)
                    stack.push(hex::decode(op_code).unwrap()); // Pushing decoded bytes to the stack
                } else if *op_code == "OP_EQUALVERIFY" { // Checking if opcode is OP_EQUALVERIFY
                    let a = stack.pop().expect("STACK UNDERFLOW: OP_EQUALVERIFY"); // Popping first operand from the stack
                    let b = stack.pop().expect("STACK UNDERFLOW: OP_EQUALVERIFY"); // Popping second operand from the stack

                    if a != b { // Checking if operands are equal
                        return false; // Returning false if operands are not equal
                    }
                } else if *op_code == "OP_CHECKSIG" { // Checking if opcode is OP_CHECKSIG
                    let result = op_checksig(&tx, tx_input_index); // Calling op_checksig function

                    if result == true { // Checking result of signature verification
                        continue; // Continuing loop if signature verification succeeds
                    } else {
                        return false; // Returning false if signature verification fails
                    }
                }
            }
        }
    }
    true // Returning true if script execution completes successfully
}

fn hash160(data: &[u8]) -> Vec<u8> {
    Ripemd160::digest(&Sha256::digest(data)).to_vec() // Computing RIPEMD160 hash of SHA256 hash of data
}

fn double_sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(&Sha256::digest(data)).to_vec() // Computing SHA256 hash of SHA256 hash of data
}

// OPCHECK_SIG OPERATION AND TRIMMED TX CREATION FOR P2PKH 
fn op_checksig(tx: &Transaction, tx_input_index: usize) -> bool {
    let mut trimmed_tx = Vec::new(); // Initializing vector for trimmed transaction

    trimmed_tx.extend(&tx.version.to_le_bytes()); // Appending transaction version to trimmed transaction
    trimmed_tx.push(tx.vin.len() as u8); // Appending number of transaction inputs to trimmed transaction

    for input_index in 0..tx.vin.len() { // Iterating over transaction inputs
        let mut txid_bytes_reversed =
            hex::decode(&tx.vin[input_index].txid).expect("DECODING FAILED"); // Decoding reversed transaction ID

        txid_bytes_reversed.reverse(); // Reversing transaction ID bytes

        trimmed_tx.extend_from_slice(&txid_bytes_reversed); // Appending transaction ID bytes to trimmed transaction
        trimmed_tx.extend(&tx.vin[input_index].vout.to_le_bytes()); // Appending transaction output index to trimmed transaction

        if input_index == tx_input_index { // Checking if current input is the one to be trimmed
            let script_pub_key_bytes =
                hex::decode(&tx.vin[input_index].prevout.scriptpubkey).expect("DECODING FAILED"); // Decoding script pubkey bytes
            trimmed_tx.push(script_pub_key_bytes.len().try_into().unwrap()); // Appending script pubkey length to trimmed transaction
            trimmed_tx.extend_from_slice(&script_pub_key_bytes); // Appending script pubkey bytes to trimmed transaction
        } else {
            trimmed_tx.push(0 as u8); // Appending 0 to indicate no script pubkey for this input
        }

        trimmed_tx.extend(&tx.vin[input_index].sequence.to_le_bytes()); // Appending sequence number to trimmed transaction
    }

    trimmed_tx.push(tx.vout.len() as u8); // Appending number of transaction outputs to trimmed transaction

    for tx_output in tx.vout.iter() { // Iterating over transaction outputs
        let script_pub_key_bytes =
            hex::decode(tx_output.scriptpubkey.clone()).expect("DECODING FAILED"); // Decoding script pubkey bytes

        trimmed_tx.extend(tx_output.value.to_le_bytes()); // Appending output value to trimmed transaction
        trimmed_tx.push(script_pub_key_bytes.len().try_into().unwrap()); // Appending script pubkey length to trimmed transaction
        trimmed_tx.extend_from_slice(&script_pub_key_bytes); // Appending script pubkey bytes to trimmed transaction
    }

    trimmed_tx.extend(&tx.locktime.to_le_bytes()); // Appending transaction locktime to trimmed transaction

    if let Some(sighash_type) = extract_sighash_type(
        tx.vin[tx_input_index]
            .scriptsig_asm
            .clone()
            .expect("SCRIPT SIG ASM: MISSING"),
    ) {
        trimmed_tx.extend(&sighash_type.to_le_bytes()); // Appending sighash type to trimmed transaction
    }

    // THE TRIMMED TRANSACTION IS READY

    let scriptsig_asm = tx.vin[tx_input_index]
        .scriptsig_asm
        .clone()
        .expect("SCRIPT SIG ASM: MISSING"); // Extracting scriptsig_asm for the input
    let scriptsig_asm_slices: Vec<&str> = scriptsig_asm.split_whitespace().collect(); // Splitting scriptsig_asm into slices

    let signature = scriptsig_asm_slices[1]; // Extracting signature from scriptsig_asm
    let pubkey = scriptsig_asm_slices[3]; // Extracting public key from scriptsig_asm

    let trimmed_tx_hash = double_sha256(&trimmed_tx); // Computing double SHA256 hash of trimmed transaction
    let signature_bytes = hex::decode(signature).expect("DECODING: FAILED"); // Decoding signature from hexadecimal
    let pubkey_bytes = hex::decode(pubkey).expect("DECODING: FAILED"); // Decoding public key from hexadecimal

    let secp = Secp256k1::new(); // Initializing secp256k1 context
    let public_key = PublicKey::from_slice(&pubkey_bytes).expect("ERROR PARSING: PUBLIC KEY"); // Parsing public key
    let signature = Signature::from_der(&signature_bytes[..signature_bytes.len() - 1]).unwrap(); // Parsing signature

    let message =
        Message::from_digest_slice(&trimmed_tx_hash).expect("ERROR CREATING MESSAGE FROM TX_HASH"); // Creating message from trimmed transaction hash

    match secp.verify_ecdsa(&message, &signature, &public_key) { // Verifying signature
        Ok(_) => {
            return true; // Returning true if signature verification succeeds
        }
        Err(_) => return false, // Returning false if signature verification fails
    }
}

// EXTRACTS THE SIGHASH TYPE FROM THE LAST OF THE SIGNATURE
fn extract_sighash_type(scriptsig_asm: String) -> Option<u32> {
    let scriptsig_slices: Vec<&str> = scriptsig_asm.split_whitespace().collect(); // Splitting scriptsig_asm into slices
    let signature = scriptsig_slices[1]; // Extracting signature from scriptsig_asm
    let sig_bytes = hex::decode(signature).ok()?; // Decoding signature bytes
    let sighash_type = sig_bytes.last().copied().expect("NOT FOUND") as u32; // Extracting last byte as sighash type

    Some(sighash_type) // Returning sighash type
}

// TO TEST MY CODE DURING DEVELOPMENT
#[cfg(test)]
mod test {
    use std::fs;

    use super::*;
    use walkdir::WalkDir;

    #[test]
    fn test_script_execution_p2pkh() -> Result<()> {
        let mut s_count = 0; // Initializing success count
        let mut f_count = 0; // Initializing failure count

        let mempool_dir = "./mempool"; // Path to mempool directory
        for entry in WalkDir::new(mempool_dir).into_iter().filter_map(|e| e.ok()) { // Iterating over mempool directory
            let path = entry.path(); // Getting path of current file
            if path.is_file() { // Checking if it's a file
                match fs::read_to_string(path) { // Reading file contents
                    Ok(contents) => {
                        match serde_json::from_str::<Transaction>(&contents) { // Parsing JSON into Transaction struct
                            Ok(transaction) => {
                                let all_p2sh = transaction.clone().vin.iter().all(|input| { // Checking if all inputs are of type p2pkh
                                    input.prevout.scriptpubkey_type == "p2pkh".to_string()
                                });

                                let mut tx_result = true; // Initializing transaction result flag

                                if all_p2sh { // Proceeding if all inputs are of type p2pkh
                                    for input_index in 0..transaction.vin.len() { // Iterating over transaction inputs
                                        let scriptsig_asm = transaction.clone().vin[input_index]
                                            .scriptsig_asm
                                            .clone()
                                            .expect("ASM: MISSING"); // Extracting scriptsig_asm

                                        let tx = transaction.clone();
                                        let result = script_execution( // Calling script_execution function
                                            tx.vin[input_index].prevout.scriptpubkey_asm.clone(),
                                            scriptsig_asm,
                                            tx,
                                            input_index,
                                        );
                                        if result == false { // Checking result of script execution
                                            tx_result = false; // Setting transaction result flag to false
                                            break; // Breaking loop if script execution fails
                                        }
                                    }

                                    if tx_result == true { // Checking transaction result
                                        s_count += 1; // Incrementing success count
                                    } else {
                                        f_count += 1; // Incrementing failure count
                                    }

                                    // println!("\n\n");
                                }
                            }
                            Err(e) => {
                                println!("Failed to parse JSON: {}", e); // Handling JSON parsing error
                            }
                        }
                    }
                    Err(e) => eprintln!("Failed to read file: {}", e), // Handling file reading error
                }
            }
        }

        println!("success: {}", s_count); // Printing success count
        println!("failure: {}", f_count); // Printing failure count

        Ok(()) // Returning Ok result
    }

    #[test]
    fn test2() -> Result<()> {
        let path =
            "./mempool/01f16e8312f9c882e869d31a3ab386b94a38f6091f7e947c6f2ed2b3389f4406.json";

        // Read the JSON file
        let data = fs::read_to_string(path).expect("Unable to read file");

        // Deserialize JSON into Rust data structures
        let transaction: Transaction = serde_json::from_str(&data)?;

        let scriptsig_asm = transaction.clone().vin[0]
            .scriptsig_asm
            .clone()
            .expect("ASM: MISSING");

        let tx = transaction.clone();
        let result = script_execution(
            tx.vin[0].prevout.scriptpubkey_asm.clone(),
            scriptsig_asm,
            tx,
            0,
        );

        println!("{}", result);

        Ok(())
    }
}
