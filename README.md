# Rust-Shell-Launcher

A high-performance Rust-based shellcode launcher featuring AES decryption and remote fetching capabilities. This project demonstrates secure execution techniques with encrypted payloads, emphasizing stealth and efficiency.

## Features

- **AES Encryption**: Securely encrypts and decrypts shellcode for enhanced security.
- **Remote Fetching**: Retrieves shellcode dynamically from a remote server.
- **Stealth Execution**: Runs shellcode with minimal detection footprint.
- **Performance Optimized**: Written in Rust for speed and memory safety.

## Installation

Ensure you have Rust installed on your system. If not, install it using:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Clone the repository:

```sh
git clone https://github.com/Kuasera/rust-shell-launcher.git
cd rust-shell-launcher
```

Build the project:

```sh
cargo build --release --target x86_64-pc-windows-gnu
```

## Usage

```sh
./target/release/rust-shell-launcher.exe <encrypted_shellcode> <key.txt>
```

## Disclaimer

🚨 **Educational Purposes Only!** 🚨

This project is intended solely for learning and security research. Unauthorized or malicious usage is strictly prohibited. The developers assume no responsibility for misuse.

## License

This project is open-source and available under the MIT License.
