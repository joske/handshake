use handshake::HandshakeState;
use std::error::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::dh::from_handshake_name;

static PSK: &[u8] = b"XTSPPFrCk7sZmBFm8Hm6cXjjS7Ddd3PV";
const NAME: &str = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s";

pub mod aes;
pub mod chacha;
pub mod cipher;
pub mod dh;
pub mod handshake;
pub mod hasher;
pub mod pattern;
pub mod symmetric;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut static_key = from_handshake_name(NAME)?;
    static_key.generate();
    let mut handshake_state = HandshakeState::new(NAME, static_key, PSK, &[])?;
    let payload = [];
    let mut message = vec![0u8; 1024];
    println!("connect to server");
    let mut socket = TcpStream::connect("127.0.0.1:9999").await?;
    println!("start handshake");
    let len = handshake_state.write_message(&payload, &mut message)?;
    write(&mut socket, &message[..len]).await?;
    let response = read(&mut socket).await?;
    handshake_state.read_message(&response, &mut message)?;
    let len = handshake_state.write_message(&payload, &mut message)?;
    write(&mut socket, &message[..len]).await?;
    println!("handshake done");
    let len = handshake_state.write_message(b"You should hire me!", &mut message)?;
    write(&mut socket, &message[..len]).await?;
    println!("Sent encypted message to server");
    let response = read(&mut socket).await?;
    let len = handshake_state.read_message(&response, &mut message)?;
    println!(
        "server responded with: {}",
        String::from_utf8_lossy(&message[..len])
    );
    Ok(())
}

// simple server transport protocol is 2 bytes (Big Endian) for length and then exactly that amount of bytes

async fn read(socket: &mut TcpStream) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut len = [0u8; 2];
    socket.read_exact(&mut len).await?;
    let size = u16::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; size];
    socket.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write(socket: &mut TcpStream, buf: &[u8]) -> Result<(), Box<dyn Error>> {
    let len = (buf.len() as u16).to_be_bytes();
    socket.write_all(&len).await?;
    socket.write_all(buf).await?;
    Ok(())
}
