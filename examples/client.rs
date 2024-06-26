use std::error::Error;
use tokio::net::TcpStream;

use handshake::{dh::from_handshake_name, handshake::HandshakeState};

mod common;

static PSK: [u8; 32] = *b"XTSPPFrCk7sZmBFm8Hm6cXjjS7Ddd3PV";
const NAME: &str = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut static_key = from_handshake_name(NAME)?;
    static_key.generate();
    let mut handshake_state = HandshakeState::new(NAME, static_key, Some(PSK), &[], true)?;
    let payload = [];
    let mut message = vec![0u8; 1024];
    println!("connect to server");
    let mut socket = TcpStream::connect("127.0.0.1:9999").await?;

    println!("start handshake");
    let len = handshake_state.write_message(&payload, &mut message)?;
    common::write(&mut socket, &message[..len]).await?;
    let response = common::read(&mut socket).await?;
    handshake_state.read_message(&response, &mut message)?;
    let len = handshake_state.write_message(&payload, &mut message)?;
    common::write(&mut socket, &message[..len]).await?;
    println!("handshake done");

    let mut codec = handshake_state.into_transport_mode()?;

    let len = codec.encrypt(b"You should hire me!", &mut message)?;
    common::write(&mut socket, &message[..len]).await?;
    println!("Sent encypted message to server");
    let response = common::read(&mut socket).await?;
    let len = codec.decrypt(&response, &mut message)?;
    println!("server responded with: {}", String::from_utf8_lossy(&message[..len]));
    Ok(())
}
