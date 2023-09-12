use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

// simple server transport protocol is 2 bytes (Big Endian) for length and then exactly that amount of bytes

pub async fn read(socket: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    socket.read_exact(&mut len).await?;
    let size = u16::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; size];
    socket.read_exact(&mut buf).await?;
    Ok(buf)
}

pub async fn write(socket: &mut TcpStream, buf: &[u8]) -> std::io::Result<()> {
    let len = (buf.len() as u16).to_be_bytes();
    socket.write_all(&len).await?;
    socket.write_all(buf).await?;
    Ok(())
}

#[allow(dead_code)]
pub fn main() {}
