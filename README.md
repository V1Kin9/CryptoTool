# CryptoTool

A comprehensive cryptography tool with PyQt5 GUI, implementing standard cryptographic functions using the Python `cryptography` library.

## Features

CryptoTool provides a user-friendly graphical interface for various cryptographic operations:

### 1. Symmetric Encryption
- **Algorithms**: AES-256-CBC, AES-256-GCM
- **Operations**: 
  - Encrypt/decrypt text messages
  - Generate random encryption keys
  - Save/load keys from files
  - Base64 encoding for easy sharing

### 2. Asymmetric Encryption
- **Algorithm**: RSA (2048, 3072, 4096-bit keys)
- **Operations**:
  - Encrypt messages with public key
  - Decrypt messages with private key
  - OAEP padding with SHA-256

### 3. Digital Signatures
- **Algorithm**: RSA-PSS with SHA-256
- **Operations**:
  - Sign messages with private key
  - Verify signatures with public key
  - Base64 encoded signatures

### 4. Key Generation
- **RSA Key Pairs**: Generate 2048, 3072, or 4096-bit RSA key pairs
- **Key Management**:
  - View generated keys
  - Save keys to PEM files
  - Load keys from PEM files

### 5. Key Exchange
- **Algorithm**: Diffie-Hellman (2048, 3072, 4096-bit)
- **Operations**:
  - Generate DH key pairs
  - Share public keys
  - Compute shared secrets
  - Use shared secret for symmetric encryption

### 6. Hash Functions
- **Algorithms**: SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512
- **Operations**:
  - Compute cryptographic hashes
  - Hexadecimal output format

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Install Dependencies

```bash
pip install -r requirements.txt
```

This will install:
- `cryptography>=42.0.4` - Python cryptography library
- `PyQt5>=5.15.0` - GUI framework

## Usage

### Running the Application

```bash
python3 crypto_tool.py
```

Or make it executable and run directly:

```bash
chmod +x crypto_tool.py
./crypto_tool.py
```

### Basic Workflow

1. **Symmetric Encryption**:
   - Go to "Symmetric Encryption" tab
   - Click "Generate Key" to create a random key
   - Enter your plaintext message
   - Click "Encrypt" to encrypt
   - Copy the Base64 ciphertext
   - Paste ciphertext and click "Decrypt" to decrypt

2. **Asymmetric Encryption**:
   - Go to "Key Generation" tab first
   - Select key size and click "Generate RSA Key Pair"
   - Go to "Asymmetric Encryption" tab
   - Enter message and click "Encrypt (Public Key)"
   - Copy ciphertext, paste and click "Decrypt (Private Key)"

3. **Digital Signatures**:
   - Generate RSA keys (if not already done)
   - Go to "Digital Signatures" tab
   - Enter message and click "Sign (Private Key)"
   - Signature appears in the signature field
   - Click "Verify (Public Key)" to verify

4. **Key Exchange**:
   - Go to "Key Exchange" tab
   - Click "Generate DH Key Pair"
   - Share your public key with the other party
   - Paste their public key in the peer field
   - Click "Compute Shared Secret"
   - Use the shared secret as a symmetric key

5. **Hashing**:
   - Go to "Hash Functions" tab
   - Enter text to hash
   - Select algorithm
   - Click "Compute Hash"

## Testing

Run the test suite to verify all cryptographic functions:

```bash
python3 test_crypto.py
```

This tests:
- AES-256-CBC encryption/decryption
- AES-256-GCM encryption/decryption
- RSA encryption/decryption
- Digital signature generation/verification
- Key serialization/deserialization
- Diffie-Hellman key exchange
- Hash functions (SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512)

## Security Notes

- This tool uses industry-standard cryptographic algorithms from the `cryptography` library
- Private keys are never encrypted when saved - store them securely
- Symmetric keys are 256-bit (32 bytes) for AES encryption
- RSA uses OAEP padding for encryption and PSS padding for signatures
- All keys and encrypted data can be saved/loaded using Base64 encoding
- Use strong key sizes (at least 2048-bit for RSA, 256-bit for AES)

## Project Structure

```
CryptoTool/
├── crypto_tool.py      # Main GUI application
├── test_crypto.py      # Test suite for cryptographic functions
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

## Requirements

- Python 3.8+
- cryptography>=42.0.4
- PyQt5>=5.15.0

## License

This project is provided as-is for educational and practical cryptographic purposes.

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.
