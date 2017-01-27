#!/usr/bin/python2
# -*- coding: utf-8 -*-

# Program: aescrypt.py
# Version: 0.1.0
# Description: Encrypt/decrypt files with AES (CBC) mode

# This program is fork repo of: https://github.com/SpotlightKid/aescrypt
# and derived from an answer to this stackoverflow.com thread:
# http://stackoverflow.com/questions/16761458/

# The MIT License (MIT)
#
# Copyright (c) 2015 Christopher Arndt
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import print_function, unicode_literals

import argparse
import os
import struct
import sys

from getpass import getpass
from os.path import exists, splitext

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from pbkdf2 import PBKDF2

 
"""__all__ = It's a list of public objects of that module. 
It overrides the default of hiding everything that begins with an underscore
"""
__all__ = ("encrypt", "decrypt")
SALT_MARKER = b"$" # header
ITERATIONS = 1000


# Encrypt Function
##################
def encrypt(in_file, out_file, password, key_size=32, salt_marker=SALT_MARKER,
        kdf_iterations=ITERATIONS, hash_type=SHA256):
    """Encryption algorithm: AES Cipher-block-chaining (CBC) mode

    Key: The password given as input, the key is derived via the PBKDF2 
    key derivation function (KDF) from the password and a random salt of 16 bytes 
    (the AES block size) minus the length of the salt header (see below).

    Key size: may be 16, 24 or 32 (default).

    Hash function: The hash function used by PBKDF2 is SHA256 per default. 
    You can pass a different hash function module via the ``hashmod`` argument. 
    The module must adhere to the Python API for Cryptographic Hash Functions (PEP 247)

    About PBKDF2: PBKDF2 uses a number of iterations of the hash function 
    to derive the key, which can be set via the ``kdf_iterations` keyword argument. 
    The default number is 1000 and the maximum 65535.

    Header and Salt: The header and the salt are written to the first block 
    of the encrypted file. The header consist of the number of KDF iterations 
    encoded as a big-endian word bytes wrapped by ``salt_marker`` on both sides.
    With the default value of ``salt_marker = b'$'``, the header size is thus 4 
    and the salt 12 bytes. The salt marker must be a byte string of 1-6 bytes length.

    Padding: the last block of the encrypted file is padded with up to 16 bytes,
    all having the value of the length of the padding.
    """

    # check value of salt_marker
    if not 1 <= len(salt_marker) <= 6:
        raise ValueError("The salt_marker value must be 1 to 6 bytes long.")
        # isinstance > https://docs.python.org/2/library/functions.html
    elif not isinstance(salt_marker, bytes):
        raise TypeError("salt_marker value must be a byte instance.")

    # KDF iterations
    if kdf_iterations >= 65536:
        raise ValueError("kdf_iterations value must be <= 65535.")

    # Assign values
    ###############
    bs = AES.block_size
    header = salt_marker + struct.pack(">H", kdf_iterations) + salt_marker
    """struct = Return a string containing the value of kdf_iterations
    packed to big-endian format ">"
    """
    salt = os.urandom(bs - len(header))
    kdf = PBKDF2(password, salt, min(kdf_iterations, 65535), hash_type)
    key = kdf.read(key_size)
    iv = os.urandom(bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    out_file.write(header + salt)
    out_file.write(iv)
    finished = False

    # encrypt !
    ###########
    while not finished:
        chunk = in_file.read(1024 * bs)

        # check and adjust padding_lenght value
        if len(chunk) == 0 or len(chunk) % bs != 0:
            padding_lenght = (bs - len(chunk) % bs) or bs
            chunk += (padding_lenght * chr(padding_lenght)).encode()
            finished = True

        out_file.write(cipher.encrypt(chunk))


# Decrypt function
##################
def decrypt(in_file, out_file, password, key_size=32, salt_marker=SALT_MARKER,
        hash_type=SHA256):
    """Decrypt input file using password to derive key.
    See `Encrypt` for documentation of the encryption algorithm
    """
    mlen = len(salt_marker)
    hlen = mlen * 2 + 2

    # check salt_marker value
    if not 1 <= mlen <= 6:
        raise ValueError("The salt_marker value must be 1 to 6 bytes long.")
    elif not isinstance(salt_marker, bytes):
        raise TypeError("salt_marker value must be a bytes instance.")

    # assign values
    bs = AES.block_size
    salt = in_file.read(bs)

    # adjust salt and KDF iterations
    if salt[:mlen] == salt_marker and salt[mlen + 2:hlen] == salt_marker:
        kdf_iterations = struct.unpack(">H", salt[mlen:mlen + 2])[0]
        salt = salt[hlen:]
    else:
        kdf_iterations = ITERATIONS

    if kdf_iterations >= 65536:
        raise ValueError("kdf_iterations value must be <= 65535.")

    iv = in_file.read(bs)
    kdf = PBKDF2(password, salt, kdf_iterations, hash_type)
    key = kdf.read(key_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = b""
    finished = False

    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))

        # adjust padding
        if not next_chunk:
            padlen = chunk[-1]
            if isinstance(padlen, str):
                padlen = ord(padlen)
                padding = padlen * chr(padlen)
            else:
                padding = (padlen * chr(chunk[-1])).encode()

            if padlen < 1 or padlen > bs:
                raise ValueError("bad decrypt pad (%d)" % padlen)

            # all the pad-bytes must be the same
            if chunk[-padlen:] != padding:
                # this is similar to the bad decrypt:evp_enc.c
                # from openssl program: https://github.com/openssl/openssl/blob/master/crypto/evp/evp_enc.c
                raise ValueError("bad decrypt")

            chunk = chunk[:-padlen]
            finished = True

        out_file.write(chunk)


# main() function
#################
def main(args=None):
    parser = argparse.ArgumentParser(
    prog = "aescrypt.py",
    formatter_class = argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-e", "--encrypt", action="store_true",
        help="Encrypt file")
    parser.add_argument("-d", "--decrypt", action="store_true",
        help="Decrypt file")
    parser.add_argument("-f", "--force", action="store_true",
        help="Overwrite output file if it exists")
    parser.add_argument("in_file", help="Input file")

    args = parser.parse_args(args if args is not None else sys.argv[1:])

    if args.encrypt:
        args.out_file = args.in_file + ".enc"

    if args.decrypt:
            args.out_file = splitext(args.in_file)[0]

    if exists(args.out_file) and not args.force:
        print("[!] Output file '%s' exists.\n"
              "Use option '-f' to overwrite." % args.out_file)
        return 1

    # open file
    with open(args.in_file, "rb") as in_file, \
            open(args.out_file, "wb") as out_file:
        if args.decrypt:
            decrypt(in_file, out_file, getpass("Please enter passphrase: "))
        else:
            try:
                while True:
                    passwd = getpass("Please enter passphrase: ")
                    verify_passwd = getpass("Please re-enter this passphrase: ")

                    if passwd != verify_passwd:
                        print("[ Error ] The passwords you entered are not the same!")
                    else:
                        break
            except (EOFError, KeyboardInterrupt):
                return 1

            encrypt(in_file, out_file, passwd)

    return 0


if __name__ == "__main__":
    main()
