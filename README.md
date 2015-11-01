# aescrypt

A Python script to encrypt/decrypt files with symmetric AES cipher-block
chaining (CBC) mode.

## Usage

File Encryption:

    aescrypt.py [-f] infile [outfile]

File decryption:

    aescrypt.py -d [-f] infile [outfile]

### Acknowledgements

This script is derived from an answer to this StackOverflow question:

http://stackoverflow.com/questions/16761458/

I changed the key derivation function to use PBKDF2.

## License

MIT License © 2015 Christopher Arndt