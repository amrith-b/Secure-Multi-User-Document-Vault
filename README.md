# Secure Multi-User Document Vault

A secure client-server document storage system that implements mutual authentication, encryption, integrity protection, and fine-grained access control using modern cryptographic techniques.

## Overview

This project demonstrates the design and implementation of a secure multi-user document sharing system. It enables authenticated users to store, retrieve, and manage documents while enforcing confidentiality, integrity, and controlled access through cryptographic mechanisms.

The system follows a client-server architecture and simulates real-world secure storage workflows, including authentication, encryption, signing, and delegated access permissions.

This project was built as part of cybersecurity systems work and refined into a standalone secure storage project.

## Key Features

### Authentication
- Mutual TLS authentication using client and server certificates
- User authentication via digitally signed login statements
- Session-based authorization using server-issued tokens

### Confidentiality
- Documents encrypted using AES (CFB mode)
- Per-file symmetric keys generated securely
- AES keys protected via RSA key wrapping

### Integrity
- Documents signed using RSA digital signatures
- Signature verification performed before file access
- Detection of tampering or unauthorized modification

### Access Control
- File ownership tracked per document
- Time-bound delegated access permissions
- Support for:
  - Check-in access
  - Check-out access
  - Full access (both)

### Security Operations
- Enforced authorization checks on all operations
- Metadata-driven access enforcement
- Secure handling of file storage and retrieval

## Architecture

### Client
- Authenticates using private key signatures
- Interacts with server via HTTPS requests
- Performs:
  - Check-in (upload)
  - Check-out (download)
  - Grant access
  - Delete files
  - Logout

### Server
- Built with plain Flask route handlers
- Verifies user identity using public keys
- Issues session tokens
- Stores:
  - Encrypted or signed documents
  - Metadata (ownership, grants, security mode)
- Enforces:
  - Access control
  - Integrity verification
  - Decryption for authorized users


