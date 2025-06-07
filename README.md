# Standard_MUCKLE Protocol Implementation

## Overview

This repository contains the implementation of the **standard_MUCKLE** key exchange protocol as described in the paper:

> *“Standardized Muckle: Post-Quantum Secure Key Exchange Protocol”*  
> [https://eprint.iacr.org/2020/099.pdf](https://eprint.iacr.org/2020/099.pdf)

The implementation uses Botan cryptographic library primitives for message authentication codes (MAC), key derivation functions (KDF), elliptic curve Diffie-Hellman (ECDH), and multi-level KEMs (ML_KEM).

---

## Features

- Secure key exchange combining classical elliptic curve and post-quantum KEMs.
- MAC-based message authentication and verification.
- Constant-time comparison for security against timing attacks.
- Support for multiple MAC, PRF, and KDF primitives.
- Automatic secure zeroization of sensitive data on destruction.

---

## Key Classes and Functions

- `key_exchange_MUCKLE`  
  The main class implementing the protocol, responsible for initialization, message generation, message verification, and key derivation.

- `mac_sign` / `mac_verify`  
  Functions to sign and verify messages with the chosen MAC primitive.

- `prf`  
  Pseudo-random function implementation using Botan’s KDF primitives.

- `send_m0`, `recive_m0_send_m1`, `recive_m1`  
  Protocol message handling methods for the key exchange sequence.

---

## Usage

1. Instantiate the `key_exchange_MUCKLE` object with desired cryptographic parameters, including role (initializer or responder), security parameters, IDs, labels, and primitives.

2. Use `send_m0()` to generate the initial message (if initializer).

3. Use `recive_m0_send_m1()` to process the initial message and generate a response (if responder).

4. Use `recive_m1()` to process the responder’s reply (if initializer).

5. After the exchange, keys are derived and ready for secure communication.

---

## Compilation Instructions

### Dependencies

- [Botan](https://botan.randombit.net/) cryptographic library (version compatible with your code).

### How to Compile

To compile, simply link the botan library and headers to your compiler in a command like:

```bash
g++ -std=c++17 -I/path/to/botan/include -L/path/to/botan/lib -lbotan-2 standard_muckle.cpp -o standard_muckle
