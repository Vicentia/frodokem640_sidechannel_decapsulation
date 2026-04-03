#!/usr/bin/env python3
"""
Generate a FrodoKEM-640 keypair for testing.
Saves sk to frodo_sk.bin and pk to frodo_pk.bin.

Requires: pip install pqcrypto   (or liboqs Python bindings)
"""
try:
    from pqcrypto.kem.frodokem640shake import generate_keypair
    pk, sk = generate_keypair()
    with open("frodo_pk.bin", "wb") as f: f.write(pk)
    with open("frodo_sk.bin", "wb") as f: f.write(sk)
    print(f"pk ({len(pk)} bytes) to frodo_pk.bin")
    print(f"sk ({len(sk)} bytes) to frodo_sk.bin")
except ImportError:
    # Fallback: try liboqs
    try:
        import oqs
        kem = oqs.KeyEncapsulation("FrodoKEM-640-SHAKE")
        pk  = kem.generate_keypair()
        sk  = kem.export_secret_key()
        with open("frodo_pk.bin", "wb") as f: f.write(pk)
        with open("frodo_sk.bin", "wb") as f: f.write(sk)
        print(f"pk ({len(pk)} bytes) to frodo_pk.bin")
        print(f"sk ({len(sk)} bytes) to frodo_sk.bin")
    except ImportError:
        print("A package was not properly installed")