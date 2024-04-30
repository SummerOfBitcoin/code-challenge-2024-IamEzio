// Importing module for mining blocks
mod block_mine;

// Importing module for handling errors
mod error;

// Importing module for transaction processing
mod transaction;

// Importing module for validation checks
mod validation_checks;

// Importing Result type from the error module
use crate::error::Result;

// Importing the transaction verification function from validation_checks module
use crate::validation_checks::all_transaction_verification;

// Importing the function for validating block headers from block_mine module
use crate::block_mine::block::valid_block_header;

fn main() -> Result<()> {
    
    // Performing transaction verification
    all_transaction_verification()?;
    
    // Printing confirmation message for transaction verification
    println!("TRANSACTION VERIFICATION: COMPLETED");

    // Performing block mining with valid block headers
    valid_block_header()?;
    
    // Returning Ok if all operations completed successfully
    Ok(())
}
