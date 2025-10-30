#!/usr/bin/env python3
"""
Test script for CryptoTool cryptographic functions
Tests all cryptographic operations without GUI
"""

import sys
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM
from cryptography.hazmat.primitives import hashes, serialization, padding as crypto_padding, cmac, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh, ec
from cryptography.hazmat.backends import default_backend
import os


def test_symmetric_encryption():
    """Test AES symmetric encryption"""
    print("Testing Symmetric Encryption (AES-256-CBC)...")
    try:
        # Generate key
        key = os.urandom(32)
        plaintext = b"Hello, this is a test message for symmetric encryption!"
        
        # Encrypt
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad plaintext using PKCS7 padding
        padder = crypto_padding.PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding using PKCS7 unpadder
        unpadder = crypto_padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(padded_decrypted) + unpadder.finalize()
        
        assert plaintext == decrypted, "Decrypted text doesn't match original"
        print("✓ Symmetric encryption test passed")
        return True
    except Exception as e:
        print(f"✗ Symmetric encryption test failed: {e}")
        return False


def test_symmetric_encryption_gcm():
    """Test AES-GCM symmetric encryption"""
    print("\nTesting Symmetric Encryption (AES-256-GCM)...")
    try:
        # Generate key
        key = os.urandom(32)
        plaintext = b"Hello, this is a test message for GCM mode!"
        
        # Encrypt
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        
        assert plaintext == decrypted, "Decrypted text doesn't match original"
        print("✓ Symmetric encryption (GCM) test passed")
        return True
    except Exception as e:
        print(f"✗ Symmetric encryption (GCM) test failed: {e}")
        return False


def test_aes_128_192():
    """Test AES-128 and AES-192 encryption"""
    print("\nTesting AES-128 and AES-192...")
    try:
        plaintext = b"Test message for different key sizes"
        
        # Test AES-128
        key_128 = os.urandom(16)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key_128), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        padder = crypto_padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key_128), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = crypto_padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(padded_decrypted) + unpadder.finalize()
        
        assert plaintext == decrypted, "AES-128 decryption failed"
        
        # Test AES-192
        key_192 = os.urandom(24)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key_192), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        padder = crypto_padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key_192), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = crypto_padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(padded_decrypted) + unpadder.finalize()
        
        assert plaintext == decrypted, "AES-192 decryption failed"
        
        print("✓ AES-128 and AES-192 test passed")
        return True
    except Exception as e:
        print(f"✗ AES-128/192 test failed: {e}")
        return False


def test_cipher_modes():
    """Test different cipher modes"""
    print("\nTesting Cipher Modes (ECB, CFB, OFB, CTR, CCM)...")
    try:
        key = os.urandom(32)
        plaintext = b"Test message for cipher modes"
        
        # Test ECB (WARNING: ECB is insecure, included only for testing/educational purposes)
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = crypto_padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = crypto_padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(padded_decrypted) + unpadder.finalize()
        assert plaintext == decrypted, "ECB mode failed"
        
        # Test CFB
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        assert plaintext == decrypted, "CFB mode failed"
        
        # Test OFB
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        assert plaintext == decrypted, "OFB mode failed"
        
        # Test CTR
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        assert plaintext == decrypted, "CTR mode failed"
        
        # Test CCM
        nonce = os.urandom(13)
        aesccm = AESCCM(key, tag_length=16)
        ciphertext = aesccm.encrypt(nonce, plaintext, None)
        
        # Decrypt
        decrypted = aesccm.decrypt(nonce, ciphertext, None)
        assert plaintext == decrypted, "CCM mode failed"
        
        print("✓ Cipher modes test passed")
        return True
    except Exception as e:
        print(f"✗ Cipher modes test failed: {e}")
        return False


def test_mac_functions():
    """Test MAC functions (CMAC, CBC-MAC, GMAC, HMAC)"""
    print("\nTesting MAC Functions...")
    try:
        key = os.urandom(32)
        message = b"Test message for MAC"
        
        # Test CMAC
        c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
        c.update(message)
        mac_tag = c.finalize()
        
        c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
        c.update(message)
        c.verify(mac_tag)
        
        # Test CBC-MAC
        iv = bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = crypto_padding.PKCS7(128).padder()
        padded = padder.update(message) + padder.finalize()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        cbc_mac = ciphertext[-16:]
        assert len(cbc_mac) == 16, "CBC-MAC length incorrect"
        
        # Test GMAC (GCM with empty plaintext)
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(message)
        encryptor.finalize()
        gmac_tag = encryptor.tag
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, gmac_tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(message)
        decryptor.finalize()
        
        # Test HMAC
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(message)
        hmac_tag = h.finalize()
        
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(message)
        h.verify(hmac_tag)
        
        print("✓ MAC functions test passed")
        return True
    except Exception as e:
        print(f"✗ MAC functions test failed: {e}")
        return False


def test_ecdsa():
    """Test ECDSA signing and verification"""
    print("\nTesting ECDSA...")
    try:
        message = b"Test message for ECDSA"
        
        # Test with P-256
        private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
        public_key = private_key.public_key()
        
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        
        # Test with P-384
        private_key = ec.generate_private_key(ec.SECP384R1(), backend=default_backend())
        public_key = private_key.public_key()
        
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        
        # Test with P-521
        private_key = ec.generate_private_key(ec.SECP521R1(), backend=default_backend())
        public_key = private_key.public_key()
        
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        
        print("✓ ECDSA test passed")
        return True
    except Exception as e:
        print(f"✗ ECDSA test failed: {e}")
        return False


def test_rsa_encryption():
    """Test RSA asymmetric encryption"""
    print("\nTesting RSA Asymmetric Encryption...")
    try:
        # Generate keys
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        plaintext = b"Secret message for RSA encryption"
        
        # Encrypt with public key
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt with private key
        decrypted = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        assert plaintext == decrypted, "Decrypted text doesn't match original"
        print("✓ RSA encryption test passed")
        return True
    except Exception as e:
        print(f"✗ RSA encryption test failed: {e}")
        return False


def test_digital_signature():
    """Test RSA digital signatures"""
    print("\nTesting Digital Signatures...")
    try:
        # Generate keys
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        message = b"Message to be signed"
        
        # Sign with private key
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Verify with public key
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        print("✓ Digital signature test passed")
        return True
    except Exception as e:
        print(f"✗ Digital signature test failed: {e}")
        return False


def test_key_serialization():
    """Test RSA key serialization and deserialization"""
    print("\nTesting Key Serialization...")
    try:
        # Generate keys
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Deserialize keys
        loaded_private = serialization.load_pem_private_key(
            private_pem,
            password=None,
            backend=default_backend()
        )
        
        loaded_public = serialization.load_pem_public_key(
            public_pem,
            backend=default_backend()
        )
        
        # Test that loaded keys work
        message = b"Test message"
        ciphertext = loaded_public.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        decrypted = loaded_private.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        assert message == decrypted, "Serialization/deserialization failed"
        print("✓ Key serialization test passed")
        return True
    except Exception as e:
        print(f"✗ Key serialization test failed: {e}")
        return False


def test_diffie_hellman():
    """Test Diffie-Hellman key exchange"""
    print("\nTesting Diffie-Hellman Key Exchange...")
    try:
        # Generate parameters (using 2048-bit for security)
        parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        
        # Party A generates keys
        private_key_a = parameters.generate_private_key()
        public_key_a = private_key_a.public_key()
        
        # Party B generates keys
        private_key_b = parameters.generate_private_key()
        public_key_b = private_key_b.public_key()
        
        # Both parties compute shared secret
        shared_secret_a = private_key_a.exchange(public_key_b)
        shared_secret_b = private_key_b.exchange(public_key_a)
        
        assert shared_secret_a == shared_secret_b, "Shared secrets don't match"
        print("✓ Diffie-Hellman key exchange test passed")
        return True
    except Exception as e:
        print(f"✗ Diffie-Hellman key exchange test failed: {e}")
        return False


def test_hash_functions():
    """Test hash functions"""
    print("\nTesting Hash Functions...")
    try:
        message = b"Message to hash"
        
        # Test SHA-256
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(message)
        hash_sha256 = digest.finalize()
        
        # Test SHA-384
        digest = hashes.Hash(hashes.SHA384(), backend=default_backend())
        digest.update(message)
        hash_sha384 = digest.finalize()
        
        # Test SHA-512
        digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
        digest.update(message)
        hash_sha512 = digest.finalize()
        
        # Test SHA3-256
        digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
        digest.update(message)
        hash_sha3_256 = digest.finalize()
        
        # Test SHA3-512
        digest = hashes.Hash(hashes.SHA3_512(), backend=default_backend())
        digest.update(message)
        hash_sha3_512 = digest.finalize()
        
        # Verify different algorithms produce different hashes
        hashes_list = [hash_sha256, hash_sha384, hash_sha512, hash_sha3_256, hash_sha3_512]
        assert len(set(hashes_list)) == 5, "Hash functions produced duplicate results"
        
        print("✓ Hash functions test passed")
        return True
    except Exception as e:
        print(f"✗ Hash functions test failed: {e}")
        return False


def main():
    """Run all tests"""
    print("=" * 60)
    print("CryptoTool - Cryptographic Functions Test Suite")
    print("=" * 60)
    
    tests = [
        test_symmetric_encryption,
        test_symmetric_encryption_gcm,
        test_aes_128_192,
        test_cipher_modes,
        test_mac_functions,
        test_ecdsa,
        test_rsa_encryption,
        test_digital_signature,
        test_key_serialization,
        test_diffie_hellman,
        test_hash_functions,
    ]
    
    results = []
    for test in tests:
        results.append(test())
    
    print("\n" + "=" * 60)
    print(f"Test Results: {sum(results)}/{len(results)} passed")
    print("=" * 60)
    
    if all(results):
        print("\n✓ All tests passed!")
        return 0
    else:
        print("\n✗ Some tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
