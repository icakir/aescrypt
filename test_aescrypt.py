#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test suite for aescrypt.py."""

from __future__ import print_function, unicode_literals

from io import BytesIO

from aescrypt import encrypt, decrypt
from Crypto.Cipher import AES

from nose.tools import raises

password = 'q1w2e3r4'
plaintext = """\
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque at euismod
tortor, quis finibus mauris. Suspendisse dui augue, hendrerit at porttitor
viverra, pulvinar ut velit. Quisque facilisis felis sed felis vestibulum, sit
amet varius est vulputate. Curabitur venenatis dapibus risus, a molestie magna
lobortis et. Donec a nulla in ligula sagittis dapibus et quis velit. Curabitur
tincidunt faucibus lorem in viverra. Sed diam diam, suscipit sit amet quam nec,
cursus sollicitudin est. Vestibulum condimentum gravida sem eget tincidunt.
Nulla tincidunt massa in consectetur blandit. Ut sed nunc sed neque posuere
porttitor. Fusce et libero pretium, facilisis ante eget, fermentum enim. Sed
dignissim libero quis ultricies iaculis. Nunc eu lobortis tellus. Nam et cursus
ligula. Sed vitae consequat nisl. Cras tempor nisl non metus commodo, vitae
scelerisque neque congue.
"""
infn = 'test_input.txt'
encfn = 'test_input.txt.enc'
outfn = 'test_output.txt'


def test_roundtrip():
    """AES file encryption/decryption roundtrip produces identical files."""

    with open(infn, 'rb') as infile, open(encfn, 'wb') as outfile:
        encrypt(infile, outfile, password)

    with open(encfn, 'rb') as infile, open(outfn, 'wb') as outfile:
        decrypt(infile, outfile, password)

    with open(infn, 'rb') as original, open(outfn, 'rb') as copy:
        assert original.read() == copy.read()

@raises(ValueError)
def test_bad_decrypt():
    """Trying to decrypt invalid input raises ValueError."""
    with BytesIO(plaintext[:256].encode()) as infile, BytesIO() as outfile:
        decrypt(infile, outfile, password)

def test_key_size():
    """Key sizes of 128, 192 and 256 bit produce valid ciphertexts."""
    infile = BytesIO(plaintext.encode())

    for key_size in AES.key_size:
        cipherfile = BytesIO()
        encrypt(infile, cipherfile, password, key_size=key_size)
        infile.seek(0)
        ciphertext = cipherfile.getvalue()
        assert len(ciphertext) % 16 == 0
        cipherfile.seek(0)
        outfile = BytesIO()
        decrypt(cipherfile, outfile, password, key_size=key_size)
        decrypted = outfile.getvalue().decode('utf-8')
        assert decrypted == plaintext

def test_salt_marker():
    """Setting the salt marker produces valid header."""
    marker = b'test'
    infile = BytesIO(plaintext.encode())
    cipherfile = BytesIO()
    encrypt(infile, cipherfile, password, salt_marker=marker)
    ciphertext = cipherfile.getvalue()
    assert ciphertext[:4] == marker and ciphertext[6:10] == marker

@raises(ValueError)
def test_salt_marker_empty():
    """Passing empty salt marker raises ValueError."""
    marker = b''
    infile = BytesIO(plaintext.encode())
    cipherfile = BytesIO()
    encrypt(infile, cipherfile, password, salt_marker=marker)

@raises(ValueError)
def test_salt_marker_toolong():
    """Passing too long salt marker raises ValueError."""
    marker = b'iamlong'
    infile = BytesIO(plaintext.encode())
    cipherfile = BytesIO()
    encrypt(infile, cipherfile, password, salt_marker=marker)

@raises(TypeError)
def test_salt_marker_notbytes():
    """Passing not bytes-type salt marker raises TypeError."""
    marker = '$'
    infile = BytesIO(plaintext.encode())
    cipherfile = BytesIO()
    encrypt(infile, cipherfile, password, salt_marker=marker)

def test_kdf_iterations():
    """Passed kdf_iterations are set correctly in header."""
    infile = BytesIO(plaintext.encode())
    cipherfile = BytesIO()
    encrypt(infile, cipherfile, password, kdf_iterations=1000)
    assert cipherfile.getvalue()[1:3] == b'\x03\xe8'

@raises(ValueError)
def test_kdf_iterations_tolow():
    """Setting kdf_iterations too low raises ValueError."""
    infile = BytesIO(plaintext.encode())
    cipherfile = BytesIO()
    encrypt(infile, cipherfile, password, kdf_iterations=0)

@raises(ValueError)
def test_kdf_iterations_tohigh():
    """Setting kdf_iterations too high raises ValueError."""
    infile = BytesIO(plaintext.encode())
    cipherfile = BytesIO()
    encrypt(infile, cipherfile, password, kdf_iterations=65536)
