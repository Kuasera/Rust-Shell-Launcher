# Rust-Shell-Launcher

A high-performance Rust-based shellcode launcher featuring AES decryption and remote fetching capabilities. This project demonstrates secure execution techniques with encrypted payloads, emphasizing stealth and efficiency.

## Features

- **AES-256 Encryption & Decryption**: Secure shellcode execution using AES-256-CBC.
- **Remote Fetching**: Retrieves encrypted shellcode and decryption keys dynamically from a remote server.
- **Memory Allocation & Execution**: Uses Windows API functions (`VirtualAlloc`, `VirtualProtect`, `CreateThread`, `WaitForSingleObject`) for shellcode execution.
- **Obfuscation Support**: Implements `obfstr!` for string obfuscation.

## Installation

Ensure you have Rust installed on your system. If not, install it using:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Clone the repository:

```sh
git clone https://github.com/kuasera/rust-shell-launcher.git
cd rust-shell-launcher
```

Build the project:

```sh
cargo build --release --target x86_64-pc-windows-gnu
```

The program will fetch the encrypted shellcode and decryption key from the provided remote URLs, decrypt the shellcode, allocate executable memory, and execute it in a new thread.

⚠️ **Make sure to replace the `key.txt link` and `shellcode.bin link` with your own before running the program!**

## Windows API Functions Used

- `VirtualAlloc`: Allocates memory for the decrypted shellcode.
- `VirtualProtect`: Changes memory permissions to executable.
- `CreateThread`: Creates a new thread to execute the shellcode.
- `WaitForSingleObject`: Waits for thread completion.

## Disclaimer

🚨 **Educational Purposes Only!** 🚨

This project is intended solely for learning and security research. Unauthorized or malicious usage is strictly prohibited. The developers assume no responsibility for misuse.

## License

This project is open-source and available under the MIT License.
