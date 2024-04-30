use std::time::{SystemTime, UNIX_EPOCH}; // Importing necessary modules
use std::{fs::File, io::Write}; // Importing necessary modules

use num_bigint::BigUint; // Importing necessary modules
use num_traits::Num; // Importing necessary modules

use crate::{block_mine::serialise_tx::double_sha256, error::Result}; // Importing necessary modules

use super::{merkle_root::generate_roots, serialise_tx::create_txid_tx_map}; // Importing necessary modules

// Convert hexadecimal representation to compact form
fn target_to_compact(target_hex: &str) -> u32 {
    // Parse the target from a hex string to a big number
    let target_bytes = hex::decode(target_hex).expect("Invalid hex string"); // Convert hexadecimal string to bytes
    let mut target_bytes = target_bytes.as_slice(); // Get a mutable reference to the byte slice

    while let Some(&0) = target_bytes.first() {
        target_bytes = &target_bytes[1..]; // Remove leading zeros
    }

    let size = target_bytes.len() as u32; // Get the length of the byte slice
    let (exp, significant) = if size <= 3 { // Determine if the size is less than or equal to 3
        (
            size,
            u32::from_be_bytes( // Convert bytes to big endian u32
                [0; 1]
                    .iter()
                    .chain(target_bytes.iter().chain(std::iter::repeat(&0))) // Add leading zeros
                    .take(4)
                    .cloned()
                    .collect::<Vec<u8>>() // Collect into a vector
                    .try_into()
                    .unwrap(),
            ),
        )
    } else {
        let significant_bytes = &target_bytes[0..3]; // Take the first three significant bytes
        let significant = u32::from_be_bytes( // Convert bytes to big endian u32
            [0; 1]
                .iter()
                .chain(significant_bytes.iter()) // Add significant bytes
                .cloned()
                .collect::<Vec<u8>>() // Collect into a vector
                .try_into()
                .unwrap(),
        );
        (size, significant)
    };

    // Adjust for Bitcoin's compact format specification
    let compact = if significant & 0x00800000 != 0 { // Check if the most significant bit is set
        (significant >> 8) | ((exp + 1) << 24) // Adjust the compact format
    } else {
        significant | (exp << 24) // Adjust the compact format
    };

    compact
}

// Create a valid block header using proof of work
pub fn valid_block_header() -> Result<()> {
    // VERSION
    let version_int: u32 = 4; // Define the version number as 4
    let version = hex::encode(version_int.to_le_bytes()); // Encode the version number in little endian hexadecimal

    // PREVIOUS BLOCK HASH
    let prev_block_hash =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string(); // Define the previous block hash

    let map = create_txid_tx_map()?; // Create a map of transaction IDs to transactions
    let (merkel_root, coinbase_tx, _, txids) = generate_roots(map.clone())?; // Generate the Merkle root, coinbase transaction, and transaction IDs

    // TIME STAMP
    let current_time = SystemTime::now(); // Get the current system time
    let since_epoch = current_time.duration_since(UNIX_EPOCH).unwrap(); // Get the duration since the Unix epoch
    let time_stamp_int = since_epoch.as_secs() as u32; // Convert the duration to seconds as u32
    let time_stamp = hex::encode(time_stamp_int.to_le_bytes()); // Encode the timestamp in little endian hexadecimal

    // TARGET BITS
    let target = "0000ffff00000000000000000000000000000000000000000000000000000000"; // Define the target bits
    let target_int = BigUint::from_str_radix(target, 16).expect("INVALID HEX IN THE BLOCK"); // Parse the target bits as a big integer
    let bits = target_to_compact(target); // Convert the target bits to compact format
    let bits_hex = format!("{:08x}", bits); // Format the compact format as hexadecimal string
    let mut bits_in_bytes = hex::decode(&bits_hex)?; // Decode the compact format from hexadecimal
    bits_in_bytes.reverse(); // Reverse the bytes
    let bits_le = hex::encode(bits_in_bytes); // Encode the bytes in little endian hexadecimal

    // NONCE
    let mut nonce: u32 = 0; // Initialize the nonce to 0

    let valid_block_header: String; // Declare a variable to store the valid block header

    // POW LOGIC
    loop { // Start a loop for proof of work logic
        let nonce_hex = hex::encode(nonce.to_le_bytes()); // Convert the nonce to little endian hexadecimal

        let mut block_header: String = String::new(); // Initialize an empty string to store the block header

        block_header.push_str(&version); // Append the version to the block header
        block_header.push_str(&prev_block_hash); // Append the previous block hash to the block header
        block_header.push_str(&merkel_root); // Append the Merkle root to the block header
        block_header.push_str(&time_stamp); // Append the timestamp to the block header
        block_header.push_str(&bits_le); // Append the target bits to the block header
        block_header.push_str(&nonce_hex); // Append the nonce to the block header

        let mut block_hash_bytes = double_sha256(&hex::decode(&block_header)?); // Calculate the double SHA-256 hash of the block header
        block_hash_bytes.reverse(); // Reverse the bytes

        let block_hash = hex::encode(block_hash_bytes); // Encode the block hash as hexadecimal

        let block_hash_int =
            BigUint::from_str_radix(&block_hash, 16).expect("Invalid hex in block hash"); // Parse the block hash as a big integer

        if block_hash_int <= target_int { // Check if the block hash meets the target
            println!("Valid nonce found: {}", nonce); // Print the valid nonce
            valid_block_header = block_header; // Store the valid block header
            break; // Exit the loop
        }

        nonce += 1; // Increment the nonce
    }

    // PUT THE BLOCK HEADER, COINBASE TX, AND TXIDS IN THE OUTPUT.TXT FILE
    let mut block_file = File::create("./output.txt")?; // Create or open the output.txt file for writing

    println!("{}", txids.len()); // Print the number of transaction IDs

    writeln!(block_file, "{}", valid_block_header)?; // Write the valid block header to the file
    writeln!(block_file, "{}", coinbase_tx)?; // Write the coinbase transaction to the file

    for txid in txids { // Iterate over each transaction ID
        writeln!(block_file, "{}", txid)?; // Write each transaction ID to the file
    }

    Ok(()) // Return Ok indicating success
}
