## node handshake

clone repo

```
git clone https://github.com/joske/handshake.git
cd handshake
```

run server

```
cargo run --example server
```

run client:

```
cargo run --example server
```

Server and client share the same PSK and use the `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s` pattern. I tested other cipher/hash combinations too (non-exhaustive).

The client handles the handshake and then sends an encrypted message to the server (transport mode) and receives an encrypted response. To verify the handshake was successful, check the console output of the client and server.
