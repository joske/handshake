use std::error::Error;
use tokio::net::{TcpListener, TcpStream};

use handshake::dh::from_handshake_name;
use handshake::handshake::HandshakeState;

static PSK: [u8; 32] = *b"XTSPPFrCk7sZmBFm8Hm6cXjjS7Ddd3PV";
const NAME: &str = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s";

mod common;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    run_server().await
}

async fn run_server() -> Result<(), Box<dyn Error>> {
    // wait on client's arrival
    println!("Listening on 0.0.0.0:9999");
    let tcp_listener = TcpListener::bind("0.0.0.0:9999").await?;
    loop {
        if let Some((stream, addr)) = tcp_listener
            .accept()
            .await
            .map_err(|e| eprintln!("error during accept: {:?}", e))
            .ok()
        {
            tokio::spawn(async move {
                handle_client(stream, addr)
                    .await
                    .map_err(|e| eprintln!("error handling client: {:?}", e))
                    .ok();
            });
        }
    }
}

async fn handle_client(
    mut socket: TcpStream,
    addr: std::net::SocketAddr,
) -> Result<(), Box<dyn Error>> {
    println!("Client connected from {}", addr);
    let mut static_key = from_handshake_name(NAME)?;
    static_key.generate();
    let mut handshake_state = HandshakeState::new(NAME, static_key, Some(PSK), &[], false)?;
    println!("start handshake");

    let mut message = vec![0u8; 1024];
    let response = common::read(&mut socket).await?;
    handshake_state.read_message(&response, &mut message)?;

    let payload = [];
    let len = handshake_state.write_message(&payload, &mut message)?;
    common::write(&mut socket, &message[..len]).await?;

    let response = common::read(&mut socket).await?;
    handshake_state.read_message(&response, &mut message)?;
    println!("handshake done");

    let mut codec = handshake_state.into_transport_mode()?;

    while let Ok(request) = common::read(&mut socket).await {
        let len = codec.decrypt(&request, &mut message)?;
        println!("Client said: {}", String::from_utf8_lossy(&message[..len]));
        let len = codec.encrypt(b"Yes!", &mut message)?;
        common::write(&mut socket, &message[..len]).await?;
        println!("Sent encypted message to client");
    }
    Ok(())
}
