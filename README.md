# CryptoTool

A comprehensive cryptography tool with PyQt5 GUI, implementing standard cryptographic functions using the Python `cryptography` library.

## Features

CryptoTool provides a user-friendly graphical interface for various cryptographic operations:

### 1. Symmetric Encryption
- **Algorithms**: AES with 128-bit, 192-bit, and 256-bit keys
- **Cipher Modes**: 
  - CBC (Cipher Block Chaining)
  - GCM (Galois/Counter Mode)
  - ECB (Electronic Codebook)
  - CFB (Cipher Feedback)
  - OFB (Output Feedback)
  - CTR (Counter)
  - CCM (Counter with CBC-MAC)
- **Features**:
  - Encrypt/decrypt text messages
  - Generate random encryption keys (128/192/256-bit)
  - Save/load keys from files
  - IV/Nonce generation and handling
  - AAD (Additional Authenticated Data) support for AEAD modes (GCM, CCM)
  - Authentication tags for authenticated encryption

### 2. MAC Functions
- **Algorithms**:
  - CMAC (Cipher-based MAC) with AES
  - CBC-MAC with AES
  - GMAC (Galois MAC) with AES
  - HMAC with SHA-256, SHA-384, SHA-512
- **Operations**:
  - Compute MAC tags
  - Verify MAC authenticity
  - Support for 128/192/256-bit keys (AES-based MACs)
  - AAD support for GMAC

### 3. Asymmetric Encryption
- **Algorithm**: RSA (2048, 3072, 4096-bit keys)
- **Operations**:
  - Encrypt messages with public key
  - Decrypt messages with private key
  - OAEP padding with SHA-256 (PKCS#1 standard)

### 4. Digital Signatures
- **Algorithms**: 
  - RSA-PSS with SHA-256
  - ECDSA (Elliptic Curve Digital Signature Algorithm)
- **ECDSA Curves**:
  - P-256 (secp256r1) - NIST recommended
  - P-384 (secp384r1) - NIST recommended
  - P-521 (secp521r1) - NIST recommended
- **Operations**:
  - Sign messages with private key
  - Verify signatures with public key
  - Base64/HEX encoded signatures

### 5. Key Generation
- **RSA Key Pairs**: Generate 2048, 3072, or 4096-bit RSA key pairs
- **ECDSA Key Pairs**: Generate keys using NIST curves (P-256, P-384, P-521)
- **Key Management**:
  - View generated keys
  - Save keys to PEM files (PKCS#8 format)
  - Load keys from PEM files

### 6. Key Exchange
- **Algorithm**: Diffie-Hellman (2048, 3072, 4096-bit)
- **Operations**:
  - Generate DH key pairs
  - Share public keys
  - Compute shared secrets
  - Use shared secret for symmetric encryption

### 7. Hash Functions
- **Algorithms**: SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512
- **Operations**:
  - Compute cryptographic hashes
  - Hexadecimal output format

### 8. Data Format Conversion
- **Supported Formats**: HEX, Base64, Text
- **Operations**:
  - Convert between formats
  - Add/remove HEX prefixes (0x)

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
   - Select key size (128/192/256-bit) and cipher mode
   - Click "Generate Key" to create a random key
   - Enter your plaintext message
   - For AEAD modes (GCM/CCM), optionally add AAD
   - Click "Encrypt" to encrypt
   - Copy the HEX ciphertext
   - Paste ciphertext and click "Decrypt" to decrypt

2. **MAC Functions**:
   - Go to "MAC Functions" tab
   - Select MAC algorithm (CMAC, CBC-MAC, GMAC, HMAC)
   - Generate or enter a key
   - Enter message to authenticate
   - Click "Compute MAC" to generate authentication tag
   - Click "Verify MAC" to verify authenticity

3. **Asymmetric Encryption**:
   - Go to "Key Generation" tab first
   - Select key size and click "Generate RSA Key Pair"
   - Go to "Asymmetric Encryption" tab
   - Enter message and click "Encrypt (Public Key)"
   - Copy ciphertext, paste and click "Decrypt (Private Key)"

4. **Digital Signatures**:
   - Generate RSA or ECDSA keys (if not already done)
   - Go to "Digital Signatures" tab
   - Select algorithm (RSA-PSS or ECDSA)
   - Enter message and click "Sign (Private Key)"
   - Signature appears in the signature field
   - Click "Verify (Public Key)" to verify

5. **ECDSA Key Generation**:
   - Go to "Key Generation" tab
   - Select NIST curve (P-256, P-384, or P-521)
   - Click "Generate ECDSA Key Pair"
   - Save/load keys as needed

6. **Key Exchange**:
   - Go to "Key Exchange" tab
   - Click "Generate DH Key Pair"
   - Share your public key with the other party
   - Paste their public key in the peer field
   - Click "Compute Shared Secret"
   - Use the shared secret as a symmetric key

7. **Hashing**:
   - Go to "Hash Functions" tab
   - Enter text to hash
   - Select algorithm
   - Click "Compute Hash"

## Testing

Run the comprehensive test suite to verify all cryptographic functions:

```bash
python3 test_crypto.py
```

This tests:
- AES-128, AES-192, AES-256 encryption/decryption
- All cipher modes (CBC, GCM, ECB, CFB, OFB, CTR, CCM)
- MAC functions (CMAC, CBC-MAC, GMAC, HMAC)
- ECDSA with multiple curves (P-256, P-384, P-521)
- RSA encryption/decryption
- Digital signature generation/verification
- Key serialization/deserialization
- Diffie-Hellman key exchange
- Hash functions (SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512)

All 11 test functions should pass.

## Security Notes

- This tool uses industry-standard cryptographic algorithms from the `cryptography` library
- Private keys are saved in PKCS#8 format (unencrypted) - store them securely
- Symmetric keys support 128, 192, and 256-bit lengths
- RSA uses OAEP padding for encryption and PSS padding for signatures (NIST/PKCS standards)
- ECDSA uses NIST-recommended curves (P-256, P-384, P-521)
- All keys and encrypted data can be saved/loaded using HEX or Base64 encoding
- Use strong key sizes (at least 2048-bit for RSA, 256-bit for AES)
- AEAD modes (GCM, CCM) provide both confidentiality and authenticity
- ECB mode is included for educational purposes but should not be used in production

## Project Structure

```
CryptoTool/
├── crypto_tool.py      # Main GUI application
├── test_crypto.py      # Comprehensive test suite for cryptographic functions
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

## Requirements

- Python 3.8+
- cryptography>=42.0.4
- PyQt5>=5.15.0

## Standards Compliance

- **RSA**: PKCS#1 (OAEP, PSS), PKCS#8 key format
- **ECDSA**: NIST FIPS 186-4 recommended curves
- **AES**: NIST FIPS 197
- **MAC**: NIST SP 800-38B (CMAC), NIST SP 800-38D (GMAC), FIPS 198-1 (HMAC)
- **Hash Functions**: NIST FIPS 180-4 (SHA-2), NIST FIPS 202 (SHA-3)

## License

This project is provided as-is for educational and practical cryptographic purposes.

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.
