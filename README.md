# An implementation based on SAH-3

Algorithms:
• SHA-3 derived function KMACXOF256;
• ECDHIES encryption and Schnorr signatures;

Objective: implement (in Java) a library and an app for asymmetric encryption and digital signatures at the 256-bit
security level

# What this program will do:

1. Compute a plain cryptographic hash of a given file.

2. Compute a plain cryptographic hash of text input by the user directly to the app (instead of having to be read from a
   file).

3. Compute an authentication tag (MAC) of a given file under a given passphrase.

4. Compute an authentication tag (MAC) of text input by the user directly to the app (instead of having to be read from
   a file) under a given passphrase.

5. Encrypt a given data file symmetrically under a given passphrase.

6. Decrypt a given symmetric cryptogram under a given passphrase.

# How to use:

#### Compute a plain cryptographic hash:

`-h -f <file path>` -- the program will compute a plain cryptographic hash of the file located on given path

`-h -s <string>` -- the program will compute a plain cryptographic hash of a given string

`-h` -- you will be asked to input a string, then the program will compute a plain cryptographic hash of a given string

#### Compute an authentication tag:

`-t -f <file path> -p <passphrase>` -- the program will compute an authentication tag of the file located on given path
with the given passphrase

`-t -f <file path>` -- same as above, but you will be prompted to input a passphrase manually

`-t -s <string> -p <passphrase>` -- the program will compute an authentication tag of a given string with the given
passphrase

`-t -s <string>` -- same as above, but you will be prompted to input a passphrase manually

`-t` -- you will be asked to input a string and a passphrase, then the program will compute an authentication tag of a
given string with the given passphrase

#### Encryption:

`-e -f <input file path> -p <passphrase> -o <output file path>` -- the program will encrypt the file located on given
path with the given passphrase, and then save to given location

`-e -f <input file path> -o <output file path>` -- same as above, but you will be prompted to input a passphrase
manually

`-e -f <input file path>` -- same as above, but the encrypted data will only be printed to console, and not save to
local disk.

#### Decryption:

`-d -f <file path> -p <passphrase>` -- the program will decrypt the file located on given path with the given passphrase

`-d -f <file path>` -- same as above, but you will be prompted to input a passphrase manually



> The mode argument such as "-h" or "-t" has to be entered as the first argument! The other arguments can be entered
> in different orders, but following the order listed above are highly recommended!

