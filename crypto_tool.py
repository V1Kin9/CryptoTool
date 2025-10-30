#!/usr/bin/env python3
"""
CryptoTool - A comprehensive cryptography tool with PyQt5 GUI
Implements standard cryptography functions using the Python cryptography library
"""

import sys
import base64
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QLineEdit, QPushButton, QTextEdit, QFileDialog,
    QMessageBox, QComboBox, QGroupBox
)
from PyQt5.QtCore import Qt

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM
from cryptography.hazmat.primitives import hashes, serialization, padding as crypto_padding, cmac, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh, ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os


class CryptoTool(QMainWindow):
    """Main application window for CryptoTool"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptoTool - Cryptography Suite")
        self.setGeometry(100, 100, 900, 700)
        
        # Initialize key storage
        self.rsa_private_key = None
        self.rsa_public_key = None
        self.dh_private_key = None
        self.dh_public_key = None
        self.ec_private_key = None
        self.ec_public_key = None
        
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        # Create tab widget
        tabs = QTabWidget()
        layout.addWidget(tabs)
        
        # Add tabs for different functions
        tabs.addTab(self.create_symmetric_tab(), "Symmetric Encryption")
        tabs.addTab(self.create_mac_tab(), "MAC Functions")
        tabs.addTab(self.create_asymmetric_tab(), "Asymmetric Encryption")
        tabs.addTab(self.create_signature_tab(), "Digital Signatures")
        tabs.addTab(self.create_key_gen_tab(), "Key Generation")
        tabs.addTab(self.create_key_exchange_tab(), "Key Exchange")
        tabs.addTab(self.create_hash_tab(), "Hash Functions")
        tabs.addTab(self.create_data_format_tab(), "Data Format")
    
    def create_symmetric_tab(self):
        """Create symmetric encryption/decryption tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Algorithm selection
        algo_group = QGroupBox("Algorithm Settings")
        algo_layout = QVBoxLayout()
        algo_group.setLayout(algo_layout)
        
        # Key size selection
        key_size_layout = QHBoxLayout()
        key_size_layout.addWidget(QLabel("Key Size:"))
        self.sym_key_size_combo = QComboBox()
        self.sym_key_size_combo.addItems(["128-bit (AES-128)", "192-bit (AES-192)", "256-bit (AES-256)"])
        self.sym_key_size_combo.setCurrentIndex(2)  # Default to 256-bit
        self.sym_key_size_combo.currentIndexChanged.connect(self.update_key_size_hint)
        key_size_layout.addWidget(self.sym_key_size_combo)
        algo_layout.addLayout(key_size_layout)
        
        # Cipher mode selection
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("Cipher Mode:"))
        self.sym_mode_combo = QComboBox()
        self.sym_mode_combo.addItems(["CBC", "GCM", "ECB", "CFB", "OFB", "CTR", "CCM"])
        self.sym_mode_combo.currentIndexChanged.connect(self.update_mode_fields)
        mode_layout.addWidget(self.sym_mode_combo)
        algo_layout.addLayout(mode_layout)
        
        layout.addWidget(algo_group)
        
        # Key input
        self.key_group = QGroupBox("Key (HEX format)")
        key_layout = QVBoxLayout()
        self.key_group.setLayout(key_layout)
        
        self.sym_key_input = QLineEdit()
        self.sym_key_input.setPlaceholderText("Enter key in HEX format or generate one")
        key_layout.addWidget(self.sym_key_input)
        
        key_btn_layout = QHBoxLayout()
        gen_key_btn = QPushButton("Generate Key")
        gen_key_btn.clicked.connect(self.generate_symmetric_key)
        key_btn_layout.addWidget(gen_key_btn)
        
        save_key_btn = QPushButton("Save Key")
        save_key_btn.clicked.connect(lambda: self.save_to_file(self.sym_key_input.text(), "key"))
        key_btn_layout.addWidget(save_key_btn)
        
        load_key_btn = QPushButton("Load Key")
        load_key_btn.clicked.connect(lambda: self.load_from_file(self.sym_key_input))
        key_btn_layout.addWidget(load_key_btn)
        
        key_layout.addLayout(key_btn_layout)
        layout.addWidget(self.key_group)
        
        # AAD (Additional Authenticated Data) input for AEAD modes
        self.aad_group = QGroupBox("AAD (Additional Authenticated Data) - Optional for GCM/CCM")
        aad_layout = QVBoxLayout()
        self.aad_group.setLayout(aad_layout)
        
        self.sym_aad_input = QTextEdit()
        self.sym_aad_input.setPlaceholderText("Enter additional authenticated data (plain text)")
        self.sym_aad_input.setMaximumHeight(60)
        aad_layout.addWidget(self.sym_aad_input)
        layout.addWidget(self.aad_group)
        
        # Plaintext input
        plain_group = QGroupBox("Plaintext / Ciphertext")
        plain_layout = QVBoxLayout()
        plain_group.setLayout(plain_layout)
        
        self.sym_plaintext = QTextEdit()
        self.sym_plaintext.setPlaceholderText("Enter plaintext or ciphertext (HEX for decrypt)")
        plain_layout.addWidget(self.sym_plaintext)
        layout.addWidget(plain_group)
        
        # Buttons
        btn_layout = QHBoxLayout()
        encrypt_btn = QPushButton("Encrypt")
        encrypt_btn.clicked.connect(self.symmetric_encrypt)
        btn_layout.addWidget(encrypt_btn)
        
        decrypt_btn = QPushButton("Decrypt")
        decrypt_btn.clicked.connect(self.symmetric_decrypt)
        btn_layout.addWidget(decrypt_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(lambda: (self.sym_plaintext.clear(), self.sym_aad_input.clear()))
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        # Output
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout()
        output_group.setLayout(output_layout)
        
        self.sym_output = QTextEdit()
        self.sym_output.setReadOnly(True)
        output_layout.addWidget(self.sym_output)
        layout.addWidget(output_group)
        
        # Initialize visibility
        self.update_mode_fields()
        self.update_key_size_hint()
        
        return widget
    
    def create_mac_tab(self):
        """Create MAC functions tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # MAC algorithm selection
        algo_group = QGroupBox("MAC Algorithm")
        algo_layout = QVBoxLayout()
        algo_group.setLayout(algo_layout)
        
        algo_select_layout = QHBoxLayout()
        algo_select_layout.addWidget(QLabel("Algorithm:"))
        self.mac_algo_combo = QComboBox()
        self.mac_algo_combo.addItems(["CMAC (AES)", "CBC-MAC (AES)", "GMAC (AES)", "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512"])
        self.mac_algo_combo.currentIndexChanged.connect(self.update_mac_fields)
        algo_select_layout.addWidget(self.mac_algo_combo)
        algo_layout.addLayout(algo_select_layout)
        
        # Key size for AES-based MACs
        key_size_layout = QHBoxLayout()
        key_size_layout.addWidget(QLabel("Key Size:"))
        self.mac_key_size_combo = QComboBox()
        self.mac_key_size_combo.addItems(["128-bit", "192-bit", "256-bit"])
        self.mac_key_size_combo.setCurrentIndex(2)
        key_size_layout.addWidget(self.mac_key_size_combo)
        algo_layout.addLayout(key_size_layout)
        
        layout.addWidget(algo_group)
        
        # Key input
        key_group = QGroupBox("Key (HEX format)")
        key_layout = QVBoxLayout()
        key_group.setLayout(key_layout)
        
        self.mac_key_input = QLineEdit()
        self.mac_key_input.setPlaceholderText("Enter key in HEX format or generate one")
        key_layout.addWidget(self.mac_key_input)
        
        key_btn_layout = QHBoxLayout()
        gen_key_btn = QPushButton("Generate Key")
        gen_key_btn.clicked.connect(self.generate_mac_key)
        key_btn_layout.addWidget(gen_key_btn)
        
        save_key_btn = QPushButton("Save Key")
        save_key_btn.clicked.connect(lambda: self.save_to_file(self.mac_key_input.text(), "key"))
        key_btn_layout.addWidget(save_key_btn)
        
        load_key_btn = QPushButton("Load Key")
        load_key_btn.clicked.connect(lambda: self.load_from_file(self.mac_key_input))
        key_btn_layout.addWidget(load_key_btn)
        
        key_layout.addLayout(key_btn_layout)
        layout.addWidget(key_group)
        
        # AAD input for GMAC
        self.mac_aad_group = QGroupBox("AAD (Additional Authenticated Data) - For GMAC")
        aad_layout = QVBoxLayout()
        self.mac_aad_group.setLayout(aad_layout)
        
        self.mac_aad_input = QTextEdit()
        self.mac_aad_input.setPlaceholderText("Enter additional authenticated data (plain text)")
        self.mac_aad_input.setMaximumHeight(60)
        aad_layout.addWidget(self.mac_aad_input)
        layout.addWidget(self.mac_aad_group)
        
        # Message input
        msg_group = QGroupBox("Message")
        msg_layout = QVBoxLayout()
        msg_group.setLayout(msg_layout)
        
        self.mac_message = QTextEdit()
        self.mac_message.setPlaceholderText("Enter message to compute MAC")
        msg_layout.addWidget(self.mac_message)
        layout.addWidget(msg_group)
        
        # Buttons
        btn_layout = QHBoxLayout()
        compute_btn = QPushButton("Compute MAC")
        compute_btn.clicked.connect(self.compute_mac)
        btn_layout.addWidget(compute_btn)
        
        verify_btn = QPushButton("Verify MAC")
        verify_btn.clicked.connect(self.verify_mac)
        btn_layout.addWidget(verify_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(lambda: (self.mac_message.clear(), self.mac_aad_input.clear()))
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        # MAC output
        mac_group = QGroupBox("MAC Tag (HEX)")
        mac_layout = QVBoxLayout()
        mac_group.setLayout(mac_layout)
        
        self.mac_output = QTextEdit()
        self.mac_output.setPlaceholderText("MAC tag will appear here")
        self.mac_output.setMaximumHeight(80)
        mac_layout.addWidget(self.mac_output)
        layout.addWidget(mac_group)
        
        # Status output
        status_group = QGroupBox("Status")
        status_layout = QVBoxLayout()
        status_group.setLayout(status_layout)
        
        self.mac_status = QTextEdit()
        self.mac_status.setReadOnly(True)
        status_layout.addWidget(self.mac_status)
        layout.addWidget(status_group)
        
        # Initialize field visibility
        self.update_mac_fields()
        
        return widget
    
    def create_asymmetric_tab(self):
        """Create asymmetric encryption/decryption tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Key info
        info_label = QLabel("Use the Key Generation tab to generate RSA keys first")
        info_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(info_label)
        
        # Key status
        self.asym_key_status = QLabel("Keys: Not loaded")
        self.asym_key_status.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.asym_key_status)
        
        # Message input
        msg_group = QGroupBox("Message")
        msg_layout = QVBoxLayout()
        msg_group.setLayout(msg_layout)
        
        self.asym_message = QTextEdit()
        self.asym_message.setPlaceholderText("Enter message to encrypt or HEX ciphertext to decrypt")
        msg_layout.addWidget(self.asym_message)
        layout.addWidget(msg_group)
        
        # Buttons
        btn_layout = QHBoxLayout()
        encrypt_btn = QPushButton("Encrypt (Public Key)")
        encrypt_btn.clicked.connect(self.asymmetric_encrypt)
        btn_layout.addWidget(encrypt_btn)
        
        decrypt_btn = QPushButton("Decrypt (Private Key)")
        decrypt_btn.clicked.connect(self.asymmetric_decrypt)
        btn_layout.addWidget(decrypt_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(lambda: self.asym_message.clear())
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        # Output
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout()
        output_group.setLayout(output_layout)
        
        self.asym_output = QTextEdit()
        self.asym_output.setReadOnly(True)
        output_layout.addWidget(self.asym_output)
        layout.addWidget(output_group)
        
        return widget
    
    def create_signature_tab(self):
        """Create digital signature tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Key info
        info_label = QLabel("Use the Key Generation tab to generate RSA or ECDSA keys first")
        info_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(info_label)
        
        # Algorithm selection
        algo_group = QGroupBox("Signature Algorithm")
        algo_layout = QHBoxLayout()
        algo_group.setLayout(algo_layout)
        
        algo_layout.addWidget(QLabel("Algorithm:"))
        self.sig_algo_combo = QComboBox()
        self.sig_algo_combo.addItems(["RSA-PSS", "ECDSA"])
        algo_layout.addWidget(self.sig_algo_combo)
        layout.addWidget(algo_group)
        
        # Key status
        self.sig_key_status = QLabel("Keys: Not loaded")
        self.sig_key_status.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.sig_key_status)
        
        # Message input
        msg_group = QGroupBox("Message")
        msg_layout = QVBoxLayout()
        msg_group.setLayout(msg_layout)
        
        self.sig_message = QTextEdit()
        self.sig_message.setPlaceholderText("Enter message to sign or verify")
        msg_layout.addWidget(self.sig_message)
        layout.addWidget(msg_group)
        
        # Signature input
        sig_group = QGroupBox("Signature (HEX)")
        sig_layout = QVBoxLayout()
        sig_group.setLayout(sig_layout)
        
        self.sig_signature = QTextEdit()
        self.sig_signature.setPlaceholderText("Signature will appear here or paste for verification")
        sig_layout.addWidget(self.sig_signature)
        layout.addWidget(sig_group)
        
        # Buttons
        btn_layout = QHBoxLayout()
        sign_btn = QPushButton("Sign (Private Key)")
        sign_btn.clicked.connect(self.sign_message)
        btn_layout.addWidget(sign_btn)
        
        verify_btn = QPushButton("Verify (Public Key)")
        verify_btn.clicked.connect(self.verify_signature)
        btn_layout.addWidget(verify_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(lambda: (self.sig_message.clear(), self.sig_signature.clear()))
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        # Output
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout()
        output_group.setLayout(output_layout)
        
        self.sig_output = QTextEdit()
        self.sig_output.setReadOnly(True)
        output_layout.addWidget(self.sig_output)
        layout.addWidget(output_group)
        
        return widget
    
    def create_key_gen_tab(self):
        """Create key generation tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # RSA Key Generation
        rsa_group = QGroupBox("RSA Key Pair Generation")
        rsa_layout = QVBoxLayout()
        rsa_group.setLayout(rsa_layout)
        
        rsa_size_layout = QHBoxLayout()
        rsa_size_layout.addWidget(QLabel("Key Size:"))
        self.rsa_size_combo = QComboBox()
        self.rsa_size_combo.addItems(["2048", "3072", "4096"])
        rsa_size_layout.addWidget(self.rsa_size_combo)
        rsa_layout.addLayout(rsa_size_layout)
        
        gen_rsa_btn = QPushButton("Generate RSA Key Pair")
        gen_rsa_btn.clicked.connect(self.generate_rsa_keys)
        rsa_layout.addWidget(gen_rsa_btn)
        
        # Key display
        self.rsa_keys_display = QTextEdit()
        self.rsa_keys_display.setReadOnly(True)
        self.rsa_keys_display.setMaximumHeight(150)
        rsa_layout.addWidget(self.rsa_keys_display)
        
        # Save/Load buttons
        rsa_file_layout = QHBoxLayout()
        save_priv_btn = QPushButton("Save Private Key")
        save_priv_btn.clicked.connect(self.save_private_key)
        rsa_file_layout.addWidget(save_priv_btn)
        
        save_pub_btn = QPushButton("Save Public Key")
        save_pub_btn.clicked.connect(self.save_public_key)
        rsa_file_layout.addWidget(save_pub_btn)
        
        load_priv_btn = QPushButton("Load Private Key")
        load_priv_btn.clicked.connect(self.load_private_key)
        rsa_file_layout.addWidget(load_priv_btn)
        
        load_pub_btn = QPushButton("Load Public Key")
        load_pub_btn.clicked.connect(self.load_public_key)
        rsa_file_layout.addWidget(load_pub_btn)
        
        rsa_layout.addLayout(rsa_file_layout)
        layout.addWidget(rsa_group)
        
        # ECDSA Key Generation
        ec_group = QGroupBox("ECDSA Key Pair Generation")
        ec_layout = QVBoxLayout()
        ec_group.setLayout(ec_layout)
        
        ec_curve_layout = QHBoxLayout()
        ec_curve_layout.addWidget(QLabel("NIST Curve:"))
        self.ec_curve_combo = QComboBox()
        self.ec_curve_combo.addItems(["P-256 (secp256r1)", "P-384 (secp384r1)", "P-521 (secp521r1)"])
        ec_curve_layout.addWidget(self.ec_curve_combo)
        ec_layout.addLayout(ec_curve_layout)
        
        gen_ec_btn = QPushButton("Generate ECDSA Key Pair")
        gen_ec_btn.clicked.connect(self.generate_ec_keys)
        ec_layout.addWidget(gen_ec_btn)
        
        # EC Key display
        self.ec_keys_display = QTextEdit()
        self.ec_keys_display.setReadOnly(True)
        self.ec_keys_display.setMaximumHeight(150)
        ec_layout.addWidget(self.ec_keys_display)
        
        # EC Save/Load buttons
        ec_file_layout = QHBoxLayout()
        save_ec_priv_btn = QPushButton("Save Private Key")
        save_ec_priv_btn.clicked.connect(self.save_ec_private_key)
        ec_file_layout.addWidget(save_ec_priv_btn)
        
        save_ec_pub_btn = QPushButton("Save Public Key")
        save_ec_pub_btn.clicked.connect(self.save_ec_public_key)
        ec_file_layout.addWidget(save_ec_pub_btn)
        
        load_ec_priv_btn = QPushButton("Load Private Key")
        load_ec_priv_btn.clicked.connect(self.load_ec_private_key)
        ec_file_layout.addWidget(load_ec_priv_btn)
        
        load_ec_pub_btn = QPushButton("Load Public Key")
        load_ec_pub_btn.clicked.connect(self.load_ec_public_key)
        ec_file_layout.addWidget(load_ec_pub_btn)
        
        ec_layout.addLayout(ec_file_layout)
        layout.addWidget(ec_group)
        
        # Output
        output_group = QGroupBox("Status")
        output_layout = QVBoxLayout()
        output_group.setLayout(output_layout)
        
        self.keygen_output = QTextEdit()
        self.keygen_output.setReadOnly(True)
        output_layout.addWidget(self.keygen_output)
        layout.addWidget(output_group)
        
        return widget
    
    def create_key_exchange_tab(self):
        """Create key exchange tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # DH Parameter Generation
        dh_group = QGroupBox("Diffie-Hellman Key Exchange")
        dh_layout = QVBoxLayout()
        dh_group.setLayout(dh_layout)
        
        info_label = QLabel("Diffie-Hellman allows two parties to establish a shared secret over an insecure channel")
        info_label.setWordWrap(True)
        dh_layout.addWidget(info_label)
        
        # Key size
        size_layout = QHBoxLayout()
        size_layout.addWidget(QLabel("Key Size:"))
        self.dh_size_combo = QComboBox()
        self.dh_size_combo.addItems(["2048", "3072", "4096"])
        size_layout.addWidget(self.dh_size_combo)
        dh_layout.addLayout(size_layout)
        
        gen_dh_btn = QPushButton("Generate DH Key Pair")
        gen_dh_btn.clicked.connect(self.generate_dh_keys)
        dh_layout.addWidget(gen_dh_btn)
        
        # Public key display
        self.dh_public_display = QTextEdit()
        self.dh_public_display.setReadOnly(True)
        self.dh_public_display.setPlaceholderText("Your public key will appear here")
        self.dh_public_display.setMaximumHeight(100)
        dh_layout.addWidget(QLabel("Your Public Key (share with other party):"))
        dh_layout.addWidget(self.dh_public_display)
        
        # Peer public key input
        dh_layout.addWidget(QLabel("Peer's Public Key (HEX):"))
        self.dh_peer_public = QTextEdit()
        self.dh_peer_public.setPlaceholderText("Paste peer's public key here (HEX format)")
        self.dh_peer_public.setMaximumHeight(100)
        dh_layout.addWidget(self.dh_peer_public)
        
        compute_btn = QPushButton("Compute Shared Secret")
        compute_btn.clicked.connect(self.compute_shared_secret)
        dh_layout.addWidget(compute_btn)
        
        layout.addWidget(dh_group)
        
        # Output
        output_group = QGroupBox("Shared Secret (HEX)")
        output_layout = QVBoxLayout()
        output_group.setLayout(output_layout)
        
        self.dh_output = QTextEdit()
        self.dh_output.setReadOnly(True)
        output_layout.addWidget(self.dh_output)
        layout.addWidget(output_group)
        
        return widget
    
    def create_hash_tab(self):
        """Create hash functions tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Algorithm selection
        algo_group = QGroupBox("Hash Algorithm")
        algo_layout = QHBoxLayout()
        algo_group.setLayout(algo_layout)
        
        algo_layout.addWidget(QLabel("Algorithm:"))
        self.hash_algo_combo = QComboBox()
        self.hash_algo_combo.addItems(["SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512"])
        algo_layout.addWidget(self.hash_algo_combo)
        layout.addWidget(algo_group)
        
        # Input
        input_group = QGroupBox("Input")
        input_layout = QVBoxLayout()
        input_group.setLayout(input_layout)
        
        self.hash_input = QTextEdit()
        self.hash_input.setPlaceholderText("Enter text to hash")
        input_layout.addWidget(self.hash_input)
        layout.addWidget(input_group)
        
        # Buttons
        btn_layout = QHBoxLayout()
        hash_btn = QPushButton("Compute Hash")
        hash_btn.clicked.connect(self.compute_hash)
        btn_layout.addWidget(hash_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(lambda: self.hash_input.clear())
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        # Output
        output_group = QGroupBox("Hash (Hexadecimal)")
        output_layout = QVBoxLayout()
        output_group.setLayout(output_layout)
        
        self.hash_output = QTextEdit()
        self.hash_output.setReadOnly(True)
        output_layout.addWidget(self.hash_output)
        layout.addWidget(output_group)
        
        return widget
    
    def create_data_format_tab(self):
        """Create data format handling tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Format conversion section
        convert_group = QGroupBox("Format Conversion")
        convert_layout = QVBoxLayout()
        convert_group.setLayout(convert_layout)
        
        # Source format selection
        source_layout = QHBoxLayout()
        source_layout.addWidget(QLabel("Source Format:"))
        self.format_source_combo = QComboBox()
        self.format_source_combo.addItems(["HEX", "Base64", "Text"])
        source_layout.addWidget(self.format_source_combo)
        convert_layout.addLayout(source_layout)
        
        # Input
        convert_layout.addWidget(QLabel("Input:"))
        self.format_input = QTextEdit()
        self.format_input.setPlaceholderText("Enter data to convert")
        self.format_input.setMaximumHeight(150)
        convert_layout.addWidget(self.format_input)
        
        # Target format selection
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target Format:"))
        self.format_target_combo = QComboBox()
        self.format_target_combo.addItems(["HEX", "Base64", "Text"])
        target_layout.addWidget(self.format_target_combo)
        convert_layout.addLayout(target_layout)
        
        # Convert button
        convert_btn = QPushButton("Convert")
        convert_btn.clicked.connect(self.convert_format)
        convert_layout.addWidget(convert_btn)
        
        layout.addWidget(convert_group)
        
        # HEX prefix management section
        prefix_group = QGroupBox("HEX Prefix Management")
        prefix_layout = QVBoxLayout()
        prefix_group.setLayout(prefix_layout)
        
        prefix_layout.addWidget(QLabel("HEX Data:"))
        self.prefix_input = QTextEdit()
        self.prefix_input.setPlaceholderText("Enter HEX data (with or without 0x prefix)")
        self.prefix_input.setMaximumHeight(100)
        prefix_layout.addWidget(self.prefix_input)
        
        # Prefix buttons
        prefix_btn_layout = QHBoxLayout()
        add_prefix_btn = QPushButton("Add '0x' Prefix")
        add_prefix_btn.clicked.connect(self.add_hex_prefix)
        prefix_btn_layout.addWidget(add_prefix_btn)
        
        remove_prefix_btn = QPushButton("Remove '0x' Prefix")
        remove_prefix_btn.clicked.connect(self.remove_hex_prefix)
        prefix_btn_layout.addWidget(remove_prefix_btn)
        
        prefix_layout.addLayout(prefix_btn_layout)
        layout.addWidget(prefix_group)
        
        # Output section
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout()
        output_group.setLayout(output_layout)
        
        self.format_output = QTextEdit()
        self.format_output.setReadOnly(True)
        output_layout.addWidget(self.format_output)
        
        # Clear button
        clear_btn = QPushButton("Clear All")
        clear_btn.clicked.connect(self.clear_format_fields)
        output_layout.addWidget(clear_btn)
        
        layout.addWidget(output_group)
        
        return widget
    
    # UI Helper methods
    def update_mode_fields(self):
        """Update field visibility based on selected cipher mode"""
        mode = self.sym_mode_combo.currentText()
        # Show AAD only for AEAD modes (GCM, CCM)
        self.aad_group.setVisible(mode in ["GCM", "CCM"])
    
    def update_key_size_hint(self):
        """Update key input hint based on selected key size"""
        key_size_text = self.sym_key_size_combo.currentText()
        if "128" in key_size_text:
            hint = "Key (HEX format, 32 hex characters for AES-128)"
        elif "192" in key_size_text:
            hint = "Key (HEX format, 48 hex characters for AES-192)"
        else:
            hint = "Key (HEX format, 64 hex characters for AES-256)"
        self.key_group.setTitle(hint)
    
    def update_mac_fields(self):
        """Update field visibility based on selected MAC algorithm"""
        algo = self.mac_algo_combo.currentText()
        # Show AAD only for GMAC
        self.mac_aad_group.setVisible("GMAC" in algo)
        # Show key size only for AES-based MACs
        self.mac_key_size_combo.setEnabled("AES" in algo)
    
    def get_key_size_bytes(self):
        """Get key size in bytes from the combo box"""
        key_size_text = self.sym_key_size_combo.currentText()
        if "128" in key_size_text:
            return 16
        elif "192" in key_size_text:
            return 24
        else:
            return 32
    
    def get_mac_key_size_bytes(self):
        """Get MAC key size in bytes from the combo box"""
        key_size_text = self.mac_key_size_combo.currentText()
        if "128" in key_size_text:
            return 16
        elif "192" in key_size_text:
            return 24
        else:
            return 32
    
    # Symmetric encryption methods
    def generate_symmetric_key(self):
        """Generate a random symmetric key"""
        try:
            key_size = self.get_key_size_bytes()
            key = os.urandom(key_size)
            key_hex = key.hex()
            self.sym_key_input.setText(key_hex)
            self.sym_output.setText(f"✓ Generated new {key_size*8}-bit key")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate key: {str(e)}")
    
    def symmetric_encrypt(self):
        """Encrypt plaintext using symmetric encryption"""
        try:
            # Get key
            key_hex = self.sym_key_input.text().strip()
            if not key_hex:
                raise ValueError("Please enter or generate a key")
            
            # Clean hex input
            key_hex = self.clean_hex_input(key_hex)
            
            key = bytes.fromhex(key_hex)
            expected_key_size = self.get_key_size_bytes()
            if len(key) != expected_key_size:
                raise ValueError(f"Key must be {expected_key_size} bytes ({expected_key_size*2} hex characters)")
            
            # Get plaintext
            plaintext = self.sym_plaintext.toPlainText().encode()
            if not plaintext:
                raise ValueError("Please enter plaintext")
            
            mode = self.sym_mode_combo.currentText()
            
            # Get AAD if applicable
            aad = None
            if mode in ["GCM", "CCM"]:
                aad_text = self.sym_aad_input.toPlainText()
                if aad_text:
                    aad = aad_text.encode()
            
            if mode == "CBC":
                # Generate random IV
                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                
                # Pad plaintext to block size using PKCS7 padding
                padder = crypto_padding.PKCS7(128).padder()
                padded_plaintext = padder.update(plaintext) + padder.finalize()
                
                ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
                
                # Combine IV and ciphertext
                result = iv + ciphertext
                result_hex = result.hex()
                self.sym_output.setText(f"✓ Encryption successful (AES-CBC)\n\nCiphertext (HEX):\n{result_hex}")
                
            elif mode == "GCM":
                # Generate random nonce
                nonce = os.urandom(12)
                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
                encryptor = cipher.encryptor()
                
                if aad:
                    encryptor.authenticate_additional_data(aad)
                
                ciphertext = encryptor.update(plaintext) + encryptor.finalize()
                
                # Combine nonce, ciphertext, and tag
                result = nonce + ciphertext + encryptor.tag
                result_hex = result.hex()
                tag_hex = encryptor.tag.hex()
                self.sym_output.setText(f"✓ Encryption successful (AES-GCM)\n\nCiphertext (HEX):\n{result_hex}\n\nTag (HEX):\n{tag_hex}")
            
            elif mode == "ECB":
                # ECB mode - no IV needed
                cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
                encryptor = cipher.encryptor()
                
                # Pad plaintext to block size using PKCS7 padding
                padder = crypto_padding.PKCS7(128).padder()
                padded_plaintext = padder.update(plaintext) + padder.finalize()
                
                ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
                result_hex = ciphertext.hex()
                self.sym_output.setText(f"✓ Encryption successful (AES-ECB)\n\nCiphertext (HEX):\n{result_hex}")
            
            elif mode == "CFB":
                # Generate random IV
                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                
                ciphertext = encryptor.update(plaintext) + encryptor.finalize()
                
                # Combine IV and ciphertext
                result = iv + ciphertext
                result_hex = result.hex()
                self.sym_output.setText(f"✓ Encryption successful (AES-CFB)\n\nCiphertext (HEX):\n{result_hex}")
            
            elif mode == "OFB":
                # Generate random IV
                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                
                ciphertext = encryptor.update(plaintext) + encryptor.finalize()
                
                # Combine IV and ciphertext
                result = iv + ciphertext
                result_hex = result.hex()
                self.sym_output.setText(f"✓ Encryption successful (AES-OFB)\n\nCiphertext (HEX):\n{result_hex}")
            
            elif mode == "CTR":
                # Generate random nonce
                nonce = os.urandom(16)
                cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
                encryptor = cipher.encryptor()
                
                ciphertext = encryptor.update(plaintext) + encryptor.finalize()
                
                # Combine nonce and ciphertext
                result = nonce + ciphertext
                result_hex = result.hex()
                self.sym_output.setText(f"✓ Encryption successful (AES-CTR)\n\nCiphertext (HEX):\n{result_hex}")
            
            elif mode == "CCM":
                # Generate random nonce (7-13 bytes for CCM, using 13)
                nonce = os.urandom(13)
                aesccm = AESCCM(key, tag_length=16)
                
                ciphertext = aesccm.encrypt(nonce, plaintext, aad)
                
                # Combine nonce and ciphertext (tag is already included)
                result = nonce + ciphertext
                result_hex = result.hex()
                # Extract tag (last 16 bytes of ciphertext)
                tag_hex = ciphertext[-16:].hex()
                self.sym_output.setText(f"✓ Encryption successful (AES-CCM)\n\nCiphertext (HEX):\n{result_hex}\n\nTag (HEX):\n{tag_hex}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed: {str(e)}")
            self.sym_output.setText(f"✗ Error: {str(e)}")
    
    def symmetric_decrypt(self):
        """Decrypt ciphertext using symmetric encryption"""
        try:
            # Get key
            key_hex = self.sym_key_input.text().strip()
            if not key_hex:
                raise ValueError("Please enter or generate a key")
            
            # Clean hex input
            key_hex = self.clean_hex_input(key_hex)
            
            key = bytes.fromhex(key_hex)
            expected_key_size = self.get_key_size_bytes()
            if len(key) != expected_key_size:
                raise ValueError(f"Key must be {expected_key_size} bytes ({expected_key_size*2} hex characters)")
            
            # Get ciphertext
            ciphertext_hex = self.sym_plaintext.toPlainText().strip()
            if not ciphertext_hex:
                raise ValueError("Please enter ciphertext")
            
            # Clean hex input
            ciphertext_hex = self.clean_hex_input(ciphertext_hex)
            
            data = bytes.fromhex(ciphertext_hex)
            mode = self.sym_mode_combo.currentText()
            
            # Get AAD if applicable
            aad = None
            if mode in ["GCM", "CCM"]:
                aad_text = self.sym_aad_input.toPlainText()
                if aad_text:
                    aad = aad_text.encode()
            
            if mode == "CBC":
                if len(data) < 16:
                    raise ValueError("Invalid ciphertext")
                
                iv = data[:16]
                ciphertext = data[16:]
                
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                
                padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                
                # Remove padding using PKCS7 unpadder
                unpadder = crypto_padding.PKCS7(128).unpadder()
                plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
                
            elif mode == "GCM":
                if len(data) < 28:  # 12 (nonce) + 16 (tag)
                    raise ValueError("Invalid ciphertext")
                
                nonce = data[:12]
                tag = data[-16:]
                ciphertext = data[12:-16]
                
                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
                decryptor = cipher.decryptor()
                
                if aad:
                    decryptor.authenticate_additional_data(aad)
                
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            elif mode == "ECB":
                # ECB mode - no IV
                ciphertext = data
                
                cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
                decryptor = cipher.decryptor()
                
                padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                
                # Remove padding using PKCS7 unpadder
                unpadder = crypto_padding.PKCS7(128).unpadder()
                plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            elif mode == "CFB":
                if len(data) < 16:
                    raise ValueError("Invalid ciphertext")
                
                iv = data[:16]
                ciphertext = data[16:]
                
                cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            elif mode == "OFB":
                if len(data) < 16:
                    raise ValueError("Invalid ciphertext")
                
                iv = data[:16]
                ciphertext = data[16:]
                
                cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            elif mode == "CTR":
                if len(data) < 16:
                    raise ValueError("Invalid ciphertext")
                
                nonce = data[:16]
                ciphertext = data[16:]
                
                cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
                decryptor = cipher.decryptor()
                
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            elif mode == "CCM":
                if len(data) < 29:  # 13 (nonce) + 16 (tag)
                    raise ValueError("Invalid ciphertext")
                
                nonce = data[:13]
                ciphertext_with_tag = data[13:]  # Includes tag
                
                aesccm = AESCCM(key, tag_length=16)
                plaintext = aesccm.decrypt(nonce, ciphertext_with_tag, aad)
            
            plaintext_str = plaintext.decode()
            self.sym_output.setText(f"✓ Decryption successful\n\nPlaintext:\n{plaintext_str}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Decryption failed: {str(e)}")
            self.sym_output.setText(f"✗ Error: {str(e)}")
    
    # MAC Functions methods
    def generate_mac_key(self):
        """Generate a random MAC key"""
        try:
            algo = self.mac_algo_combo.currentText()
            if "HMAC" in algo:
                # HMAC can use any key length, but we'll use 32 bytes
                key_size = 32
            else:
                # AES-based MACs
                key_size = self.get_mac_key_size_bytes()
            
            key = os.urandom(key_size)
            key_hex = key.hex()
            self.mac_key_input.setText(key_hex)
            self.mac_status.setText(f"✓ Generated new {key_size*8}-bit key")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate key: {str(e)}")
    
    def compute_mac(self):
        """Compute MAC for the given message"""
        try:
            # Get key
            key_hex = self.mac_key_input.text().strip()
            if not key_hex:
                raise ValueError("Please enter or generate a key")
            
            key_hex = self.clean_hex_input(key_hex)
            key = bytes.fromhex(key_hex)
            
            # Get message
            message = self.mac_message.toPlainText().encode()
            if not message:
                raise ValueError("Please enter a message")
            
            algo = self.mac_algo_combo.currentText()
            
            if algo == "CMAC (AES)":
                # CMAC using AES
                c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
                c.update(message)
                mac_tag = c.finalize()
                
            elif algo == "CBC-MAC (AES)":
                # CBC-MAC is just CBC with IV=0 and taking the last block
                iv = bytes(16)  # All zeros
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                
                # Pad message to block size
                padder = crypto_padding.PKCS7(128).padder()
                padded_message = padder.update(message) + padder.finalize()
                
                ciphertext = encryptor.update(padded_message) + encryptor.finalize()
                # Take the last block as the MAC
                mac_tag = ciphertext[-16:]
                
            elif algo == "GMAC (AES)":
                # GMAC is GCM with empty plaintext
                nonce = os.urandom(12)
                
                # Get AAD
                aad = self.mac_aad_input.toPlainText().encode() if self.mac_aad_input.toPlainText() else message
                
                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
                encryptor = cipher.encryptor()
                encryptor.authenticate_additional_data(aad)
                encryptor.finalize()
                
                # Combine nonce and tag for output
                mac_tag = nonce + encryptor.tag
                
            elif "HMAC" in algo:
                # HMAC
                if "SHA256" in algo:
                    hash_algo = hashes.SHA256()
                elif "SHA384" in algo:
                    hash_algo = hashes.SHA384()
                elif "SHA512" in algo:
                    hash_algo = hashes.SHA512()
                else:
                    raise ValueError("Unknown HMAC algorithm")
                
                h = hmac.HMAC(key, hash_algo, backend=default_backend())
                h.update(message)
                mac_tag = h.finalize()
            
            mac_hex = mac_tag.hex()
            self.mac_output.setText(mac_hex)
            self.mac_status.setText(f"✓ MAC computed successfully using {algo}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"MAC computation failed: {str(e)}")
            self.mac_status.setText(f"✗ Error: {str(e)}")
    
    def verify_mac(self):
        """Verify MAC for the given message"""
        try:
            # Get key
            key_hex = self.mac_key_input.text().strip()
            if not key_hex:
                raise ValueError("Please enter or generate a key")
            
            key_hex = self.clean_hex_input(key_hex)
            key = bytes.fromhex(key_hex)
            
            # Get message
            message = self.mac_message.toPlainText().encode()
            if not message:
                raise ValueError("Please enter a message")
            
            # Get MAC tag
            mac_hex = self.mac_output.toPlainText().strip()
            if not mac_hex:
                raise ValueError("Please compute or enter a MAC tag")
            
            mac_hex = self.clean_hex_input(mac_hex)
            expected_mac = bytes.fromhex(mac_hex)
            
            algo = self.mac_algo_combo.currentText()
            
            if algo == "CMAC (AES)":
                c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
                c.update(message)
                c.verify(expected_mac)
                
            elif algo == "CBC-MAC (AES)":
                # Recompute CBC-MAC
                iv = bytes(16)
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                
                padder = crypto_padding.PKCS7(128).padder()
                padded_message = padder.update(message) + padder.finalize()
                
                ciphertext = encryptor.update(padded_message) + encryptor.finalize()
                computed_mac = ciphertext[-16:]
                
                if computed_mac != expected_mac:
                    raise ValueError("MAC verification failed")
                
            elif algo == "GMAC (AES)":
                # GMAC verification - need to extract nonce and tag
                if len(expected_mac) < 28:  # 12 (nonce) + 16 (tag)
                    raise ValueError("Invalid GMAC format")
                
                nonce = expected_mac[:12]
                tag = expected_mac[12:]
                
                aad = self.mac_aad_input.toPlainText().encode() if self.mac_aad_input.toPlainText() else message
                
                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
                decryptor = cipher.decryptor()
                decryptor.authenticate_additional_data(aad)
                decryptor.finalize()
                
            elif "HMAC" in algo:
                if "SHA256" in algo:
                    hash_algo = hashes.SHA256()
                elif "SHA384" in algo:
                    hash_algo = hashes.SHA384()
                elif "SHA512" in algo:
                    hash_algo = hashes.SHA512()
                else:
                    raise ValueError("Unknown HMAC algorithm")
                
                h = hmac.HMAC(key, hash_algo, backend=default_backend())
                h.update(message)
                h.verify(expected_mac)
            
            self.mac_status.setText("✓ MAC verification SUCCESSFUL - Message is authentic")
            QMessageBox.information(self, "Success", "MAC verification successful!")
            
        except Exception as e:
            self.mac_status.setText(f"✗ MAC verification FAILED - {str(e)}")
            QMessageBox.warning(self, "Verification Failed", f"MAC verification failed: {str(e)}")
    
    # RSA key generation methods
    def generate_rsa_keys(self):
        """Generate RSA key pair"""
        try:
            key_size = int(self.rsa_size_combo.currentText())
            
            self.keygen_output.setText(f"Generating {key_size}-bit RSA key pair... Please wait.")
            QApplication.processEvents()
            
            self.rsa_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            self.rsa_public_key = self.rsa_private_key.public_key()
            
            # Display keys
            private_pem = self.rsa_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            self.rsa_keys_display.setText(f"Private Key:\n{private_pem.decode()}\n\nPublic Key:\n{public_pem.decode()}")
            self.keygen_output.setText(f"✓ Successfully generated {key_size}-bit RSA key pair")
            
            # Update status in other tabs
            self.update_key_status()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Key generation failed: {str(e)}")
            self.keygen_output.setText(f"✗ Error: {str(e)}")
    
    def update_key_status(self):
        """Update key status labels in other tabs"""
        rsa_loaded = self.rsa_private_key and self.rsa_public_key
        ec_loaded = self.ec_private_key and self.ec_public_key
        
        if rsa_loaded and ec_loaded:
            status = "Keys: RSA and ECDSA Loaded ✓"
        elif rsa_loaded:
            status = "Keys: RSA Loaded ✓"
        elif ec_loaded:
            status = "Keys: ECDSA Loaded ✓"
        else:
            status = "Keys: Not loaded"
        
        self.asym_key_status.setText(status)
        self.sig_key_status.setText(status)
    
    def save_private_key(self):
        """Save private key to file"""
        if not self.rsa_private_key:
            QMessageBox.warning(self, "Warning", "No private key to save. Generate keys first.")
            return
        
        try:
            filename, _ = QFileDialog.getSaveFileName(self, "Save Private Key", "", "PEM Files (*.pem);;All Files (*)")
            if filename:
                pem = self.rsa_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                with open(filename, 'wb') as f:
                    f.write(pem)
                self.keygen_output.setText(f"✓ Private key saved to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save private key: {str(e)}")
    
    def save_public_key(self):
        """Save public key to file"""
        if not self.rsa_public_key:
            QMessageBox.warning(self, "Warning", "No public key to save. Generate keys first.")
            return
        
        try:
            filename, _ = QFileDialog.getSaveFileName(self, "Save Public Key", "", "PEM Files (*.pem);;All Files (*)")
            if filename:
                pem = self.rsa_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                with open(filename, 'wb') as f:
                    f.write(pem)
                self.keygen_output.setText(f"✓ Public key saved to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save public key: {str(e)}")
    
    def load_private_key(self):
        """Load private key from file"""
        try:
            filename, _ = QFileDialog.getOpenFileName(self, "Load Private Key", "", "PEM Files (*.pem);;All Files (*)")
            if filename:
                with open(filename, 'rb') as f:
                    pem_data = f.read()
                self.rsa_private_key = serialization.load_pem_private_key(
                    pem_data,
                    password=None,
                    backend=default_backend()
                )
                self.keygen_output.setText(f"✓ Private key loaded from {filename}")
                self.update_key_status()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load private key: {str(e)}")
    
    def load_public_key(self):
        """Load public key from file"""
        try:
            filename, _ = QFileDialog.getOpenFileName(self, "Load Public Key", "", "PEM Files (*.pem);;All Files (*)")
            if filename:
                with open(filename, 'rb') as f:
                    pem_data = f.read()
                self.rsa_public_key = serialization.load_pem_public_key(
                    pem_data,
                    backend=default_backend()
                )
                self.keygen_output.setText(f"✓ Public key loaded from {filename}")
                self.update_key_status()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load public key: {str(e)}")
    
    # ECDSA key generation methods
    def generate_ec_keys(self):
        """Generate ECDSA key pair"""
        try:
            curve_text = self.ec_curve_combo.currentText()
            
            # Map UI text to curve
            if "P-256" in curve_text:
                curve = ec.SECP256R1()
            elif "P-384" in curve_text:
                curve = ec.SECP384R1()
            elif "P-521" in curve_text:
                curve = ec.SECP521R1()
            else:
                raise ValueError("Unknown curve")
            
            self.keygen_output.setText(f"Generating ECDSA key pair with {curve_text}... Please wait.")
            QApplication.processEvents()
            
            self.ec_private_key = ec.generate_private_key(curve, backend=default_backend())
            self.ec_public_key = self.ec_private_key.public_key()
            
            # Display keys
            private_pem = self.ec_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = self.ec_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            self.ec_keys_display.setText(f"Private Key:\n{private_pem.decode()}\n\nPublic Key:\n{public_pem.decode()}")
            self.keygen_output.setText(f"✓ Successfully generated ECDSA key pair with {curve_text}")
            
            # Update status in other tabs
            self.update_key_status()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"ECDSA key generation failed: {str(e)}")
            self.keygen_output.setText(f"✗ Error: {str(e)}")
    
    def save_ec_private_key(self):
        """Save EC private key to file"""
        if not self.ec_private_key:
            QMessageBox.warning(self, "Warning", "No EC private key to save. Generate keys first.")
            return
        
        try:
            filename, _ = QFileDialog.getSaveFileName(self, "Save EC Private Key", "", "PEM Files (*.pem);;All Files (*)")
            if filename:
                pem = self.ec_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                with open(filename, 'wb') as f:
                    f.write(pem)
                self.keygen_output.setText(f"✓ EC private key saved to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save EC private key: {str(e)}")
    
    def save_ec_public_key(self):
        """Save EC public key to file"""
        if not self.ec_public_key:
            QMessageBox.warning(self, "Warning", "No EC public key to save. Generate keys first.")
            return
        
        try:
            filename, _ = QFileDialog.getSaveFileName(self, "Save EC Public Key", "", "PEM Files (*.pem);;All Files (*)")
            if filename:
                pem = self.ec_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                with open(filename, 'wb') as f:
                    f.write(pem)
                self.keygen_output.setText(f"✓ EC public key saved to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save EC public key: {str(e)}")
    
    def load_ec_private_key(self):
        """Load EC private key from file"""
        try:
            filename, _ = QFileDialog.getOpenFileName(self, "Load EC Private Key", "", "PEM Files (*.pem);;All Files (*)")
            if filename:
                with open(filename, 'rb') as f:
                    pem_data = f.read()
                self.ec_private_key = serialization.load_pem_private_key(
                    pem_data,
                    password=None,
                    backend=default_backend()
                )
                self.keygen_output.setText(f"✓ EC private key loaded from {filename}")
                self.update_key_status()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load EC private key: {str(e)}")
    
    def load_ec_public_key(self):
        """Load EC public key from file"""
        try:
            filename, _ = QFileDialog.getOpenFileName(self, "Load EC Public Key", "", "PEM Files (*.pem);;All Files (*)")
            if filename:
                with open(filename, 'rb') as f:
                    pem_data = f.read()
                self.ec_public_key = serialization.load_pem_public_key(
                    pem_data,
                    backend=default_backend()
                )
                self.keygen_output.setText(f"✓ EC public key loaded from {filename}")
                self.update_key_status()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load EC public key: {str(e)}")
    
    # Asymmetric encryption methods
    def asymmetric_encrypt(self):
        """Encrypt message using RSA public key"""
        try:
            if not self.rsa_public_key:
                raise ValueError("No public key loaded. Generate or load keys first.")
            
            message = self.asym_message.toPlainText().encode()
            if not message:
                raise ValueError("Please enter a message")
            
            ciphertext = self.rsa_public_key.encrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            ciphertext_hex = ciphertext.hex()
            self.asym_output.setText(f"✓ Encryption successful\n\nCiphertext (HEX):\n{ciphertext_hex}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed: {str(e)}")
            self.asym_output.setText(f"✗ Error: {str(e)}")
    
    def asymmetric_decrypt(self):
        """Decrypt message using RSA private key"""
        try:
            if not self.rsa_private_key:
                raise ValueError("No private key loaded. Generate or load keys first.")
            
            ciphertext_hex = self.asym_message.toPlainText().strip()
            if not ciphertext_hex:
                raise ValueError("Please enter ciphertext")
            
            # Clean hex input
            ciphertext_hex = self.clean_hex_input(ciphertext_hex)
            
            ciphertext = bytes.fromhex(ciphertext_hex)
            
            plaintext = self.rsa_private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            plaintext_str = plaintext.decode()
            self.asym_output.setText(f"✓ Decryption successful\n\nPlaintext:\n{plaintext_str}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Decryption failed: {str(e)}")
            self.asym_output.setText(f"✗ Error: {str(e)}")
    
    # Digital signature methods
    def sign_message(self):
        """Sign message using RSA or ECDSA private key"""
        try:
            algo = self.sig_algo_combo.currentText()
            
            message = self.sig_message.toPlainText().encode()
            if not message:
                raise ValueError("Please enter a message")
            
            if algo == "RSA-PSS":
                if not self.rsa_private_key:
                    raise ValueError("No RSA private key loaded. Generate or load RSA keys first.")
                
                signature = self.rsa_private_key.sign(
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
            elif algo == "ECDSA":
                if not self.ec_private_key:
                    raise ValueError("No ECDSA private key loaded. Generate or load ECDSA keys first.")
                
                signature = self.ec_private_key.sign(
                    message,
                    ec.ECDSA(hashes.SHA256())
                )
            
            signature_hex = signature.hex()
            self.sig_signature.setText(signature_hex)
            self.sig_output.setText(f"✓ Message signed successfully using {algo}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Signing failed: {str(e)}")
            self.sig_output.setText(f"✗ Error: {str(e)}")
    
    def verify_signature(self):
        """Verify signature using RSA or ECDSA public key"""
        try:
            algo = self.sig_algo_combo.currentText()
            
            message = self.sig_message.toPlainText().encode()
            if not message:
                raise ValueError("Please enter a message")
            
            signature_hex = self.sig_signature.toPlainText().strip()
            if not signature_hex:
                raise ValueError("Please enter a signature")
            
            # Clean hex input
            signature_hex = self.clean_hex_input(signature_hex)
            signature = bytes.fromhex(signature_hex)
            
            if algo == "RSA-PSS":
                if not self.rsa_public_key:
                    raise ValueError("No RSA public key loaded. Generate or load RSA keys first.")
                
                self.rsa_public_key.verify(
                    signature,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
            elif algo == "ECDSA":
                if not self.ec_public_key:
                    raise ValueError("No ECDSA public key loaded. Generate or load ECDSA keys first.")
                
                self.ec_public_key.verify(
                    signature,
                    message,
                    ec.ECDSA(hashes.SHA256())
                )
            
            self.sig_output.setText(f"✓ Signature is VALID ({algo})")
            QMessageBox.information(self, "Success", "Signature verification successful!")
            
        except Exception as e:
            self.sig_output.setText("✗ Signature is INVALID")
            QMessageBox.warning(self, "Verification Failed", f"Signature verification failed: {str(e)}")
    
    # Diffie-Hellman key exchange methods
    def generate_dh_keys(self):
        """Generate Diffie-Hellman key pair"""
        try:
            key_size = int(self.dh_size_combo.currentText())
            
            self.dh_output.setText(f"Generating {key_size}-bit DH parameters... Please wait.")
            QApplication.processEvents()
            
            # Generate parameters (this can take a while)
            parameters = dh.generate_parameters(generator=2, key_size=key_size, backend=default_backend())
            
            # Generate private key
            self.dh_private_key = parameters.generate_private_key()
            self.dh_public_key = self.dh_private_key.public_key()
            
            # Serialize public key
            public_bytes = self.dh_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            public_hex = public_bytes.hex()
            self.dh_public_display.setText(public_hex)
            self.dh_output.setText(f"✓ Generated {key_size}-bit DH key pair")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"DH key generation failed: {str(e)}")
            self.dh_output.setText(f"✗ Error: {str(e)}")
    
    def compute_shared_secret(self):
        """Compute shared secret from peer's public key"""
        try:
            if not self.dh_private_key:
                raise ValueError("Generate your DH keys first")
            
            peer_public_hex = self.dh_peer_public.toPlainText().strip()
            if not peer_public_hex:
                raise ValueError("Please enter peer's public key")
            
            # Clean hex input
            peer_public_hex = self.clean_hex_input(peer_public_hex)
            
            peer_public_bytes = bytes.fromhex(peer_public_hex)
            peer_public_key = serialization.load_pem_public_key(
                peer_public_bytes,
                backend=default_backend()
            )
            
            shared_secret = self.dh_private_key.exchange(peer_public_key)
            shared_secret_hex = shared_secret.hex()
            
            self.dh_output.setText(f"✓ Shared secret computed\n\nShared Secret (HEX):\n{shared_secret_hex}\n\nYou can use this as a key for symmetric encryption.")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to compute shared secret: {str(e)}")
            self.dh_output.setText(f"✗ Error: {str(e)}")
    
    # Hash functions
    def compute_hash(self):
        """Compute hash of input text"""
        try:
            input_text = self.hash_input.toPlainText().encode()
            if not input_text:
                raise ValueError("Please enter text to hash")
            
            algo = self.hash_algo_combo.currentText()
            
            if algo == "SHA-256":
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            elif algo == "SHA-384":
                digest = hashes.Hash(hashes.SHA384(), backend=default_backend())
            elif algo == "SHA-512":
                digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
            elif algo == "SHA3-256":
                digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
            elif algo == "SHA3-512":
                digest = hashes.Hash(hashes.SHA3_512(), backend=default_backend())
            
            digest.update(input_text)
            hash_value = digest.finalize()
            hash_hex = hash_value.hex()
            
            self.hash_output.setText(f"✓ Hash computed using {algo}\n\n{hash_hex}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Hash computation failed: {str(e)}")
            self.hash_output.setText(f"✗ Error: {str(e)}")
    
    # Data format handling methods
    def convert_format(self):
        """Convert between different data formats"""
        try:
            input_data = self.format_input.toPlainText().strip()
            if not input_data:
                raise ValueError("Please enter data to convert")
            
            source_format = self.format_source_combo.currentText()
            target_format = self.format_target_combo.currentText()
            
            # Convert source to bytes
            if source_format == "HEX":
                # Clean hex input
                hex_data = self.clean_hex_input(input_data)
                try:
                    data_bytes = bytes.fromhex(hex_data)
                except ValueError:
                    raise ValueError("Invalid HEX format")
            elif source_format == "Base64":
                try:
                    data_bytes = base64.b64decode(input_data)
                except Exception:
                    raise ValueError("Invalid Base64 format")
            elif source_format == "Text":
                data_bytes = input_data.encode('utf-8')
            
            # Convert bytes to target format
            if target_format == "HEX":
                result = data_bytes.hex()
            elif target_format == "Base64":
                result = base64.b64encode(data_bytes).decode()
            elif target_format == "Text":
                try:
                    result = data_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    raise ValueError("Cannot decode data as text (not valid UTF-8)")
            
            self.format_output.setText(f"✓ Conversion successful\n\n{result}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Conversion failed: {str(e)}")
            self.format_output.setText(f"✗ Error: {str(e)}")
    
    def add_hex_prefix(self):
        """Add 0x prefix to HEX data"""
        try:
            input_data = self.prefix_input.toPlainText().strip()
            if not input_data:
                raise ValueError("Please enter HEX data")
            
            # Remove existing prefix if any
            # Clean hex input
            hex_data = self.clean_hex_input(input_data)
            
            # Validate hex
            try:
                bytes.fromhex(hex_data)
            except ValueError:
                raise ValueError("Invalid HEX format")
            
            result = "0x" + hex_data
            self.format_output.setText(f"✓ Prefix added\n\n{result}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add prefix: {str(e)}")
            self.format_output.setText(f"✗ Error: {str(e)}")
    
    def remove_hex_prefix(self):
        """Remove 0x prefix from HEX data"""
        try:
            input_data = self.prefix_input.toPlainText().strip()
            if not input_data:
                raise ValueError("Please enter HEX data")
            
            # Clean hex input
            hex_data = self.clean_hex_input(input_data)
            
            # Validate hex
            try:
                bytes.fromhex(hex_data)
            except ValueError:
                raise ValueError("Invalid HEX format")
            
            self.format_output.setText(f"✓ Prefix removed\n\n{hex_data}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to remove prefix: {str(e)}")
            self.format_output.setText(f"✗ Error: {str(e)}")
    
    # Utility methods
    def clean_hex_input(self, hex_string):
        """Clean HEX input by removing whitespace and optional 0x prefix"""
        hex_clean = hex_string.replace(" ", "").replace("\n", "")
        if hex_clean.lower().startswith("0x"):
            hex_clean = hex_clean[2:]
        return hex_clean
    
    def clear_format_fields(self):
        """Clear all fields in the Data Format tab"""
        self.format_input.clear()
        self.prefix_input.clear()
        self.format_output.clear()
    
    def save_to_file(self, data, file_type):
        """Save data to file"""
        try:
            if not data:
                QMessageBox.warning(self, "Warning", f"No {file_type} to save")
                return
            
            filename, _ = QFileDialog.getSaveFileName(self, f"Save {file_type}", "", "Text Files (*.txt);;All Files (*)")
            if filename:
                with open(filename, 'w') as f:
                    f.write(data)
                QMessageBox.information(self, "Success", f"{file_type.capitalize()} saved to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save {file_type}: {str(e)}")
    
    def load_from_file(self, target_widget):
        """Load data from file into widget"""
        try:
            filename, _ = QFileDialog.getOpenFileName(self, "Load File", "", "Text Files (*.txt);;All Files (*)")
            if filename:
                with open(filename, 'r') as f:
                    data = f.read()
                target_widget.setText(data)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load file: {str(e)}")


def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    window = CryptoTool()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
