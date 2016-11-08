### aescrypt

#### A Python 2 script to encrypt/decrypt files with symmetric AES cipher-block chaining (CBC) mode.

```
usage: aescrypt.py [-h] [-e] [-d] [-f] in_file

positional arguments:
  in_file        Input file

optional arguments:
  -h, --help     show this help message and exit
  -e, --encrypt  Encrypt file
  -d, --decrypt  Decrypt file
  -f, --force    Overwrite output file if it exists


Examples:

Encrypt file:

./aescrypt.py -e <file name>


Decrypt file:

./aescrypt.py -d <file name>.enc



#### Acknowledgements

This script is derived from an answer to this StackOverflow question:

http://stackoverflow.com/questions/16761458/




#### License

MIT License © 2015 Christopher Arndt
