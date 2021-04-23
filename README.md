# AmES

## Warning

I am not a cryptography or cyber security expert, nor have I had any formal training in either of these fields. AmES has not been reviewed by cryptography or cyber security experts.
AmES is meant as a demonstration of key-dependent algorithms and as an exercise for the author.
I do not recommend using AmES for any cryptography applications.

Use at your own risk!

## Wat

AmES, Amateur Encryption Standard, is a proof of concept demonstrating a key dependent varient of the AES algorithm. Like AES it is substitution-permutation network comprised of four types of 
steps. Each step is key dependent, and even the number and order of the steps is decided by the key. Here is how each step differs

## SubBytes

AES uses a hard-coded S-box (Rijndael S-Box) which combines the multiplicative inverse followed by an affine transformation. The affine transformation is itself based on the key.

NOTE: Since the quality of the S-Box used is extremely important in encryption algorithms and this quality cannot be guaranteed, AmES allows the use of custom S-Boxes via the `SBox` trait

## ShiftRows

AmES doesn't just shift rows, it permutes the entire matrix into a new arrangement. This permutation is key dependent, and is guaranteed to to have no fixed points.

## MixColumns

AmES uses the MixColumns step of AES, but the polynomial by which each column is multiplied is key dependent
