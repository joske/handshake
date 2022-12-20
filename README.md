## node handshake

run server (forked from https://github.com/tyrchen/simple_servers and added some improvements): 
```
git clone https://github.com/joske/simple_servers.git
cd simple_servers
cargo run -p noise -- -s
```

run client:
```
git clone https://github.com/joske/handshake.git
cd handshake
cargo run
```

Server and client share the same PSK and use the `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s` pattern. I tested other cipher/hash combinations too (non-exhaustive). 

The client handles the handshake and then sends an encrypted message to the server (transport mode) and receives an encrypted response. To verify the handshake was successful, check the console output of the client and server.