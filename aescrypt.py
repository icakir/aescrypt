#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Encrypt/decrypt files with symmetric AES cipher-block chaining (CBC) mode.

Usage:

File Encryption:

    aescrypt.py [-f] infile [outfile]

File decryption:

    aescrypt.py -d [-f] infile [outfile]

Equivalent to the following OpenSSL command line invocations:

    openssl aes-256-cbc -salt -in filename -out filename.enc

resp.

    openssl aes-256-cbc -d -in filename.enc -out filename

Source: http://stackoverflow.com/questions/16761458/

"""

from __future__ import print_function, unicode_literals

__all__ = ('encrypt', 'decrypt')

import argparse
import os
import sys

from getpass import getpass
from hashlib import md5
from os.path import exists, splitext

from Crypto.Cipher import AES
from pbkdf2 import PBKDF2


def derive_key_and_iv(password, salt, key_size, iv_length):
    d = d_i = b''
    while len(d) < key_size + iv_length:
        d_i = md5(d_i + password.encode() + salt).digest()
        d += d_i
    return d[:key_size], d[key_size:key_size + iv_length]


def encrypt(in_file, out_file, password, salt_header='Salted__', key_size=32):
    bs = AES.block_size
    salt = os.urandom(bs - len(salt_header))
    key, iv = derive_key_and_iv(password, salt, key_size, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    out_file.write(salt_header.encode() + salt)
    finished = False

    while not finished:
        chunk = in_file.read(1024 * bs)

        if len(chunk) == 0 or len(chunk) % bs != 0:
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += (padding_length * chr(padding_length)).encode()
            finished = True

        out_file.write(cipher.encrypt(chunk))


def decrypt(in_file, out_file, password, salt_header='Salted__', key_size=32):
    bs = AES.block_size
    salt = in_file.read(bs)[len(salt_header):]
    key, iv = derive_key_and_iv(password, salt, key_size, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = b''
    finished = False

    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))

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
               # this is similar to the bad decrypt:evp_enc.c from openssl program
               raise ValueError("bad decrypt")

            chunk = chunk[:-padlen]
            finished = True

        out_file.write(chunk)


def main(args=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('-d', '--decrypt', action="store_true",
        help="Decrypt input file")
    ap.add_argument('-f', '--force', action="store_true",
        help="Overwrite output file if it exists")
    ap.add_argument('infile', help="Input file")
    ap.add_argument('outfile', nargs='?', help="Input file")

    args = ap.parse_args(args if args is not None else sys.argv[1:])

    if not args.outfile:
        if args.decrypt:
            args.outfile = splitext(args.infile)[0]
        else:
            args.outfile = args.infile + '.enc'

    if args.outfile == args.infile:
        print("Input and output file must not be the same.")
        return 1

    if exists(args.outfile) and not args.force:
        print("Output file '%s' exists. "
              "Use option -f to override." % args.outfile)
        return 1

    with open(args.infile, 'rb') as infile, open(args.outfile, 'wb') as outfile:
        if args.decrypt:
            decrypt(infile, outfile, getpass("Enter decryption password: "))
        else:
            try:
                while True:
                    passwd = getpass("Enter encryption password: ")
                    passwd2 = getpass("Verify password: ")

                    if passwd != passwd2:
                        print("Password mismatch!")
                    else:
                        break
            except (EOFError, KeyboardInterrupt):
                return 1

            encrypt(infile, outfile, passwd)

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]) or 0)