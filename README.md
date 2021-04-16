# Go PQ Experiment

Just an **experiment** repro to play around to archiv a post-quantum safe system.

Warning from the used modules: We recommend to take caution before using this library in a production application since part of its content is experimental.

In high security context the German Federal Office for Information Security recommend the use of hybrid systems. 

## Idea

Use the Hybrid Public Key Encryption (HPKE) with AES and X448 in the mode authentication using both a pre-shared key (PSK) and an Asymmetric Key (mode_auth_psk) where the PSK is derived from a isogeny based drop-in replacement for Diffie–Hellman (cSIDH).

Provided one uses sufficiently large key sizes, the symmetric key cryptographic systems like AES are already resistant to attack by a quantum computer, but X448 would be broken with a sufficiently powerful quantum computer running Shor's algorithm.

With the combination of the proven Advanced Encryption Standard (AES) and the relatively new kind of elliptic-curve cryptography a hybrid system is created which is safe until both specification are broken.

### Relevant used cryptographic primitives and ciphers

1. Symmetric key cryptography
   1. Authenticated Encryption with Associated Data (AEAD)
      1. AES-256-GCM
2. Public-key cryptography
   1. elliptic-curve cryptography (ECC)
      1. commutative supersingular isogeny-based Diffie-Hellman key exchange algorithm (CSIDH)
      2. X448 with HKDF-SHA512
3. One-way hash function
   1. SHA-2
      1. SHA-512
4. Key Derivation Functions (KDFs)
   1. HKDF-SHA512

## TODO

1. AEAD ciphertexts produced by HPKE do not hide the plaintext length to archiv a level of privacy a suitable padding mechanism must be used.

## Questions

1. Must result of `csidh.DeriveSecret` be hashed to avoid weak bytes?
1. Can commutative supersingular isogeny-based Diffie-Hellman key exchange algorithm (CSIDH) be used with static keys?
2. How to use Additional Authenticated Data, the info label and the identifier for the PSK?

## Links

- https://csidh.isogeny.org/
- https://github.com/cloudflare/circl
- https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-08.html