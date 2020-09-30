extern crate crypto;
use chrono::prelude::*;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use num_bigint::BigUint;
use num_traits::One;
use std::error;
use std::fmt;
use std::process;


const HASH_BYTE_SIZE:usize=32;
type Sha256Hash=[u8; HASH_BYTE_SIZE];
const DIFFICULTY: usize = 2;
const MAX_NONCE: u64 = 1_000_000;


#[derive(Debug)]
struct Block{
    //header
    timestamp:i64,
    prev_block_hash:Sha256Hash,
    nonce:u64,

    //body
    data:Vec<u8>
}

impl Block{
    //create a new block
    fn new(data:&str, prev_hash:Sha256Hash)->Result<Self, MiningError>{
       let mut s= Self{
            prev_block_hash:prev_hash,
            data:data.to_owned().into(),
            timestamp:Utc::now().timestamp(),
            nonce:0,
        };

        s.try_hash()
        .ok_or(MiningError::Iteration)
        .and_then(|nonce|{
            s.nonce=nonce;

            Ok(s)
        })
    }

    fn try_hash(&self)->Option<u64>{
      // The target is a number we compare the hash to. It is a 256bit binary with DIFFICULTY
      // leading zeroes.
      let target=BigUint::one()<<(256-4*DIFFICULTY);

      for nonce in 0..MAX_NONCE{
          let hash=Block::calculate_hash(&self, nonce);
          let hash_int=BigUint::from_bytes_be(&hash);

          if hash_int<target{
              return Some(nonce)
          }
      }
      None
    }

    fn calculate_hash(block:&Block, nonce:u64)->Sha256Hash{
        let mut headers = block.headers();
        //convert nonce to u8 and append to header vector
          headers.extend_from_slice(&convert_u64_to_u8_array(nonce));
    
          let mut hasher = Sha256::new();
          hasher.input(&headers);
          let mut hash = Sha256Hash::default();
    
          hasher.result(&mut hash);
    
          hash
    }

    fn headers(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        //write timestamp and prev hash block to header
        vec.extend(&convert_u64_to_u8_array(self.timestamp as u64));
        vec.extend_from_slice(&self.prev_block_hash);
  
        vec
    }
    //create genesis block
    fn genesis()->Result<Self, MiningError>{
        Self::new("Genesis block", Sha256Hash::default())
    }

}

fn convert_u64_to_u8_array(val: u64) -> [u8; 8] {
    return [
        val as u8,
        (val >> 8) as u8,
        (val >> 16) as u8,
        (val >> 24) as u8,
        (val >> 32) as u8,
        (val >> 40) as u8,
        (val >> 48) as u8,
        (val >> 56) as u8,
    ]
}

#[derive(Debug)]
pub enum MiningError {
    Iteration,
    NoParent,
}

impl fmt::Display for MiningError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MiningError::Iteration => write!(f, "could not mine block, hit iteration limit"),
            MiningError::NoParent => write!(f, "block has no parent"),
        }
    }
}

impl error::Error for MiningError {
    fn description(&self) -> &str {
        match *self {
            MiningError::Iteration => "could not mine block, hit iteration limit",
            MiningError::NoParent => "block has no parent",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

pub struct Blockchain{
    blocks:Vec<Block>
}

impl Blockchain{
    //initialize the blockchain with a genesis block
    fn new()->Result<Self, MiningError>{
        let blocks=Block::genesis()?;

        Ok(Self{blocks:vec![blocks]})
    }

    //add a new block to the blockchain
    fn add_block(&mut self, data:&str)->Result<(), MiningError>{
        let block:Block;

        {
            match self.blocks.last(){
                Some(prev)=>{
                    block=Block::new(data, prev.prev_block_hash)?;
                }
                //unable to add block to the chain without a genesis block
                None=>{
                    return Err(MiningError::NoParent)
                }
            }
        }
        self.blocks.push(block);
        Ok(())
    }

    // A method that iterates over the blockchain's blocks and prints out information for each.
    fn traverse(&self) {
        for (i, block) in self.blocks.iter().enumerate() {
            println!("block: {}", i);
            println!("hash: {:?}", block.prev_block_hash);
            println!()
        }
    }
}

fn run() -> Result<(), MiningError> {
    let mut chain = Blockchain::new()?;
    println!("Send 1 RC to foo");
    chain.add_block("cool block bro!")?;
    chain.add_block("another block bro!")?;
    println!("Traversing blockchain:\n");
    chain.traverse();

    Ok(())
}

fn main() {
    run().
        unwrap_or_else(|e| {
            println!("Error: {}", e);
            process::exit(1)
        });

}
