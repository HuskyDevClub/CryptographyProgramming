# An implementation based on NIST.SP.800-185

Algorithms:
• SHA-3 derived function KMACXOF256;
• ECDHIES encryption and Schnorr signatures;

Objective: implement (in Java) a library and an app for asymmetric encryption and digital signatures at the 256-bit
security level

# Developed By:

**Yudong Lin** - The overall structure of the program, including but not limited to Glossary functions and ECDHIES encryption, and so on.

**Brian M LeSmith** - The implementation of cSHAKE256

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

### SHA-3:

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



### Elliptic curves:

#### Services the app must offer for part 2:

**Generate an elliptic key pair from a given passphrase and write the public key to a file (and also encrypt the private key from that pair under the given password and write it to a different file as well):**

`-eck -p testpw -o public.key -o2 private.key` -- generate an elliptic key pair from the given passphrase "testpw" and write the public key to "public.key" file and encrypted private key to "private.key" file.

**Encrypt a data file under a given elliptic public key file and write the ciphertext to a file:**

`-ece -f test.txt -keyp public.key -o test.txt.enc` -- the program will encrypt the "test.txt" file using previously generated "public.key" file, and then save to "test.txt.enc" file.

**Encrypt text input by the user directly to the app instead of having to read it from a file (but write the ciphertext to a file).**

`-ece -keyp public.key -o test.txt.enc` -- you will be asked to input a string which will be encrypted using previously generated "public.key" file, and then save to "test.txt.enc" file.

**Decrypt a given elliptic-encrypted file from a given password and write the decrypted data to a file.**

`-ecd -f test.txt.enc -p testpw -o test.txt` -- the program will decrypt "test.txt.enc" file with the passphrase "testpw", and then save to "test.txt"

**Sign a given file from a given password and write the signature to a file:**

`-ecs -f test.txt -p testpw -o test_signature.sign` -- the program will sign the "test.txt" file with the passphrase "testpw", and write the signature to "test_signature.sign" file.

**Sign text input by the user directly to the app instead of having to read it from a file (but write the signature to a file):**

`-ecs -p testpw -o test_signature.sign` -- you will be asked to input a string which will be signed using passphrase "testpw", and write the signature to "test_signature.sign" file.

**Verifying a signature (h, z) for a byte array m under the (Schnorr/ DHIES) public key V:**

`-ecv -f test.txt -o test_signature.sign -keyp public.key` -- Verify "test.txt" file and its signature file "test_signature.sign" under "public.key" file.

#### Generate an elliptic key pair:

`-eck -p <passphrase> -o <public key output path> -o2 <private key output path> ` -- generate an elliptic key pair from a given passphrase and write the public key and encrypted private key to given location.

`-eck -o <public key output path> -o2 <private key output path> ` -- same as above, but you will be prompted to input a passphrase manually

`-eck -o <public key output path> ` -- same as above, but the private key will only be printed to console, and will not be saved to local disk.

`-eck` -- same as above, but the  public key will only be printed to console, and will not be saved to local disk.

#### Encryption using elliptic public key:

`-ece -f <input file path> -keyp <key file path> -o <ciphertext save to path>` -- the program will encrypt the file located on given
path with the given public key, and then save to given location

`-ece -keyp <key file path> -o <ciphertext save to path>` -- same as above, but you will be asked to input a string which will be encrypted and save to given location.

`-ece -keyp <key file path>` -- same as above, but the encrypted data will only be printed to console, and will not be saved to local disk.

#### Decryption:

`-ecd -f <input file path> -p <passphrase> -o <output file path>` -- the program will decrypt the file located on given path with the given passphrase, and then save to given location

`-ecd -f <input file path> -o <output file path>` -- same as above, but you will be prompted to input a passphrase manually

`-ecd -f <input file path>` -- same as above, but the encrypted data will only be printed to console, and not save to local disk.

#### Sign:

`-ecs -f <input file path> -p <passphrase> -o <output file path>` -- the program will sign the file located on given path with the given passphrase, and write the signature to give output path.

`-ecs -p <passphrase> -o <output file path>` -- same as above, but you will be prompted to input a string which will be signed and used to generate the signature

`-ecs -o <output file path>` -- same as above, but you will be prompted to input a passphrase manually

`-ecs` -- same as above, but the signature will only be printed to console, and will not be saved to local disk.

#### Verify:

`-ecv -f <input data file path> -o <signature file path> -keyp <public key file path>` -- Verify a given data file and its signature file under a given public key file.



#### Please Note that:

> The mode argument such as "-h" or "-t" has to be entered as the first argument! The other arguments can be entered
> in different orders, but following the order listed above are highly recommended!



# Credits:

Our implementations is inspired by following repositories or documents:

https://github.com/mjosaarinen/tiny_sha3

NIST.SP.800-185

https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/cSHAKE_samples.pdf

Reference used for implementing Ed448-Goldilocks:

https://ed448goldilocks.sourceforge.net/spec/

https://github.com/otrv4/ed448/tree/master

https://github.com/Realiserad/elliptic-curve-cryptography
