use std::vec; // Import the standard `vec` module.

use hex; // Import the `hex` crate for hexadecimal encoding and decoding.
use log::info; // Import the `info` function from the `log` crate for logging purposes.

use crate::validation_checks::hash160; // Import the `hash160` function from the `validation_checks` module.
use crate::validation_checks::op_checkmultisig; // Import the `op_checkmultisig` function from the `validation_checks` module.
use crate::validation_checks::op_checksig; // Import the `op_checksig` function from the `validation_checks` module.

use crate::{error::Result, transaction::Transaction}; // Import the `Result` type and `Transaction` struct from the crate.

pub fn input_verification_p2sh(tx_input_index: usize, tx: Transaction) -> Result<bool> {
    let scriptpubkey_asm = tx.vin[tx_input_index].prevout.scriptpubkey_asm.clone(); // Clone the script pubkey ASM.

    let witness = match tx.vin[tx_input_index].witness.clone() { // Match and clone the witness data.
        Some(value) => value,
        None => Vec::new(), // If witness data is None, create an empty Vec.
    };

    let scriptsig_asm = match tx.vin[tx_input_index].scriptsig_asm.clone() { // Match and clone the scriptsig ASM.
        Some(value) => value,
        None => {
            return Ok(false); // If scriptsig ASM is None, return false.
        }
    };


    let inner_redeemscript_asm = match tx.vin[tx_input_index].inner_redeemscript_asm.clone() {
        Some(value) => value,
        None => {
            return Ok(false);
        }
    };

    Ok(script_execution_p2sh(
        scriptpubkey_asm,
        witness,
        scriptsig_asm,
        inner_redeemscript_asm,
        tx,
        tx_input_index,
    )?)
}

fn script_execution_p2sh(
    scriptpubkey_asm: String,
    witness: Vec<String>,
    scriptsig_asm: String,
    inner_redeemscript_asm: String,
    tx: Transaction,
    tx_input_index: usize,
) -> Result<bool> {
    let mut script_result: bool = false;
    let input_type: &str;

    if witness.len() == 0 {
        input_type = "NON_SEGWIT";
    } else if witness.len() == 2 {
        input_type = "P2SH-P2WPKH";
    } else {
        input_type = "P2SH-P2WSH";
    }

    let mut stack = Vec::new();

    let scriptsig_asm_opcodes: Vec<&str> = scriptsig_asm.split_whitespace().collect();
    for opcode_index in 0..scriptsig_asm_opcodes.len() {
        let is_pushbytes = scriptsig_asm_opcodes[opcode_index].starts_with("OP_PUSHBYTES");
        let is_pushdata = scriptsig_asm_opcodes[opcode_index].starts_with("OP_PUSHDATA");

        match scriptsig_asm_opcodes[opcode_index] {
            "OP_0" => {
                stack.push(vec![0 as u8]);
            }
            _ if is_pushbytes => {
                stack.push(hex::decode(&scriptsig_asm_opcodes[opcode_index + 1])?);
            }

            _ if is_pushdata => {
                stack.push(hex::decode(&scriptsig_asm_opcodes[opcode_index + 1])?);
            }
            _ => continue,
        }
    }

    let scriptpubkey_asm_opcodes: Vec<&str> = scriptpubkey_asm.split_whitespace().collect();
    for opcode_index in 0..scriptpubkey_asm_opcodes.len() {
        match scriptpubkey_asm_opcodes[opcode_index] {
            "OP_HASH160" => {
                let hash = hash160(&stack.pop().expect("STACK UNDERFLOW: OP_HASH160"));
                stack.push(hash);
            }
            "OP_PUSHBYTES_20" => {
                stack.push(
                    hex::decode(&scriptpubkey_asm_opcodes[opcode_index + 1])
                        .expect("DECODING: FAILED"),
                );
            }
            "OP_EQUAL" => {
                let a = stack.pop().expect("STACK UNDERFLOW: OP_EQUAL");
                let b = stack.pop().expect("STACK UNDERFLOW: OP_EQUAL");

                if a != b {
                    return Ok(false);
                }
            }
            _ => continue,
        }
    }


    if input_type == "NON_SEGWIT" {

        let inner_redeemscript_asm_opcodes: Vec<&str> =
            inner_redeemscript_asm.split_whitespace().collect();

        for opcode_index in 0..inner_redeemscript_asm_opcodes.len() {
            let is_pushbytes =
                inner_redeemscript_asm_opcodes[opcode_index].starts_with("OP_PUSHBYTES");

            let is_pushdata =
                inner_redeemscript_asm_opcodes[opcode_index].starts_with("OP_PUSHDATA");

            let is_equal = inner_redeemscript_asm_opcodes[opcode_index].starts_with("OP_EQUAL");

            match inner_redeemscript_asm_opcodes[opcode_index] {
                "OP_PUSHNUM_2" => stack.push(vec![2u8]),
                "OP_PUSHNUM_3" => stack.push(vec![3u8]),
                "OP_PUSHNUM_4" => stack.push(vec![4u8]),

                _ if is_pushbytes => {
                    stack.push(
                        hex::decode(&inner_redeemscript_asm_opcodes[opcode_index + 1])
                            .expect("DECODING: FAILED"),
                    );
                }

                _ if is_pushdata => {
                    stack.push(
                        hex::decode(&inner_redeemscript_asm_opcodes[opcode_index + 1])
                            .expect("DECODING: FAILED"),
                    );
                }

                "OP_0" => {
                    stack.push(vec![0 as u8]);
                }

                "OP_CSV" => {
                    continue;
                }

                "OP_DROP" => {
                    stack.pop().expect("SATCK UNDERFLOW: OP_DROP");
                }

                "OP_DUP" => stack.push(stack.last().cloned().expect("STACK UNDERFLOW")),

                "OP_HASH160" => {
                    let pk = stack.pop().expect("STACK UNDERFLOW");
                    stack.push(hash160(&pk));
                }

                _ if is_equal => {
                    let a = stack.pop().expect("STACK UNDERFLOW: OP_EQUALVERIFY");
                    let b = stack.pop().expect("STACK UNDERFLOW: OP_EQUALVERIFY");

                    if a == b {
                        script_result = true;
                    } else {
                        return Ok(false);
                    }
                }

                "OP_CHECKSIGVERIFY" => {
                    let result = op_checksig(&mut stack, tx.clone(), tx_input_index, input_type)?;

                    if result == false {
                        return Ok(false);
                    }
                }

                "OP_DEPTH" => {
                    stack.push(vec![0 as u8]);
                }

                "OP_CHECKSIG" => {
                    script_result =
                        op_checksig(&mut stack, tx.clone(), tx_input_index, input_type)?;
                }

                "OP_CHECKMULTISIG" => {
                    script_result =
                        op_checkmultisig(&mut stack, tx.clone(), tx_input_index, input_type)?;
                }
                _ => continue,
            }
        }
    }

    if input_type == "P2SH-P2WPKH" {
        stack.push(hex::decode(&witness[0]).expect("DECODING: FAILED"));

        stack.push(hex::decode(&witness[1]).expect("DECODING: FAILED"));
        stack.push(stack.last().cloned().expect("STACK UNDERFLOW"));
        let pk = stack.pop().expect("STACK UNDERFLOW");
        stack.push(hash160(&pk));

        let inner_redeemscript_opcodes: Vec<&str> =
            inner_redeemscript_asm.split_whitespace().collect();

        for opcode_index in 0..inner_redeemscript_opcodes.len() {
            match inner_redeemscript_opcodes[opcode_index] {
                "OP_0" => info!("SEGWIT VERSION: 0"),

                "OP_PUSHBYTES_20" => {
                    stack.push(
                        hex::decode(&inner_redeemscript_opcodes[opcode_index + 1])
                            .expect("DECODING: FAILED"),
                    );
                }
                _ => continue,
            }
        }

        let a = stack.pop().expect("STACK UNDERFLOW");
        let b = stack.pop().expect("STACK UNDERFLOW");

        if a != b {
            return Ok(false);
        }

        script_result = op_checksig(&mut stack, tx.clone(), tx_input_index, input_type)?;
    }

    if input_type == "P2SH-P2WSH" {
        for index in 0..witness.len() - 1 {
            stack.push(hex::decode(&witness[index])?);
        }
        let witness_script_bytes = hex::decode(&witness.last().cloned().expect("SCRIPT MISSING"))?;

        let mut index = 0;

        while index < witness_script_bytes.len() {
            let opcode = witness_script_bytes[index];
            index += 1;

            match opcode {
                82 => {
                    stack.push(vec![2u8]);
                }
                _ if opcode <= 75 as u8 && opcode >= 1 as u8 => {
                    if index + opcode as usize <= witness_script_bytes.len() {
                        let bytes = witness_script_bytes[index..index + opcode as usize].to_vec();
                        stack.push(bytes);
                        index += opcode as usize;
                    }
                }

                83 => {
                    stack.push(vec![3u8]);
                }

                174 => {
                    script_result =
                        op_checkmultisig(&mut stack, tx.clone(), tx_input_index, input_type)?;

                    if script_result == true {
                        stack.push(vec![1u8]);
                    } else {
                        stack.push(vec![0u8])
                    }
                }

                173 => {
                    let result = op_checksig(&mut stack, tx.clone(), tx_input_index, input_type)?;

                    if result == true {
                        stack.push(vec![1u8]);
                    } else {
                        stack.push(vec![0u8]);
                    }

                    let top = stack.pop().unwrap();
                    if top == vec![1u8] {
                        script_result = true;
                        continue;
                    } else {
                        return Ok(false);
                    }
                }

                172 => {
                    let sig_length = stack[stack.len() - 1].len();

                    if sig_length <= 75 && sig_length >= 70 {
                        script_result =
                            op_checksig(&mut stack, tx.clone(), tx_input_index, input_type)?;

                        if script_result == true {
                            stack.push(vec![1u8]);
                        } else {
                            stack.push(vec![0u8])
                        }
                    } else {
                        stack.push(vec![0u8]);
                    }
                }

                100 => {
                    // OP_NOTIF
                    if stack.last().cloned().unwrap_or(vec![254u8]) == vec![0u8] {
                    } else {
                        if witness_script_bytes[index] <= 75 {
                            if witness_script_bytes[index] >= 1 {
                                index += witness_script_bytes[index] as usize;
                            }
                        } else if witness_script_bytes[index] == 103 {
                            // EXECUTE THE NEXT STATEMENT
                        } else if witness_script_bytes[index] == 104 {
                            stack.pop();
                            continue;
                        }
                    }
                }

                99 => {
                    // OP_IF
                    if stack.last().cloned().unwrap_or(vec![254u8]) == vec![1u8] {
                    } else {
                        if witness_script_bytes[index] <= 75 {
                            if witness_script_bytes[index] >= 1 {
                                index += witness_script_bytes[index] as usize;
                            }
                        } else if witness_script_bytes[index] == 103 {
                            // EXECUTE THE NEXT STATEMENT
                        } else if witness_script_bytes[index] == 104 {
                            stack.pop();
                            continue;
                        }
                    }
                }

                115 => {
                    // OP_IFDUP
                    if stack.last().cloned().unwrap_or(vec![254u8]) != vec![0u8] {
                        stack.push(stack.last().cloned().expect("STACK UNDERFLOW"))
                    }
                }

                _ => continue,
            }
        }
    }
    Ok(script_result)
}

