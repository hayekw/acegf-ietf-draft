---
###
# Internet-Draft Markdown Template
#
# Rename this file from draft-todo-yourname-protocol.md to get started.
# Draft name format is "draft-<yourname>-<workgroup>-<name>.md".
#
# For initial setup, you only need to edit the first block of fields.
# Only "title" needs to be changed; delete "abbrev" if your title is short.
# Any other content can be edited, but be careful not to introduce errors.
# Some fields will be set automatically during setup if they are unchanged.
#
# Don't include "-00" or "-latest" in the filename.
# Labels in the form draft-<yourname>-<workgroup>-<name>-latest are used by
# the tools to refer to the current version; see "docname" for example.
#
# This template uses kramdown-rfc: https://github.com/cabo/kramdown-rfc
# You can replace the entire file if you prefer a different format.
# Change the file extension to match the format (.xml for XML, etc...)
#
###
title: "ACE-GF: A Generative Framework for Atomic Cryptographic Entities"
abbrev: "ACEGF"
category: info

ipr: trust200902
docname: draft-wang-acegf-protocol
submissiontype: independent
number:
date:
consensus: false
area: Security
keyword:
 - cryptographic identity
 - seed-storage-free
 - key derivation
 - post-quantum cryptography
 - autonomous digital entities

author:
 -
    fullname: Jian Sheng Wang 
    organization: Independent Researcher
    email: jason@aceft.org

normative:

informative:

--- abstract

This document defines ACE-GF (Atomic Cryptographic Entity Generative Framework),
a cryptographic construction designed to establish atomic identities for
Autonomous Digital Entities (ADEs).

The primary contribution of ACE-GF is the realization of a "Seed-Storage-Free"
architecture. By combining Misuse-Resistant Authenticated Encryption (MRAE)
with Argon2id-based password hashing, the framework encrypts the identity root,
referred to as the Root Entropy Value (REV), into a "Sealed Artifact" (SA).
The REV is reconstructed ephemerally in memory only upon successful
authorization via user credentials, thereby mitigating the systemic security
risks associated with the persistent storage of high-value master seeds.

Furthermore, the framework utilizes HKDF with explicit context encoding to
achieve robust key isolation across diverse algorithms, natively supporting
non-disruptive migration to Post-Quantum Cryptography (PQC). This
specification details the underlying data structures, derivation logic,
and recommended implementation strategies within Trusted Execution
Environments (TEEs).
--- middle

# Introduction

## Background and Motivation

Deterministic key management schemes, such as BIP-32 and BIP-39,
have simplified key recovery by deriving keys from a single
[cite_start]master seed[cite: 18]. However, these schemes rely on the
long-term persistent storage of that seed, which constitutes
[cite_start]a single point of failure (SPOF)[cite: 19, 20]. If the seed
[cite_start]is compromised, all derived keys are irreversibly exposed[cite: 21].

This storage-centric design is ill-suited for Autonomous
Digital Entities (ADEs), such as AI agents and IoT deployments,
which require identity continuity without centralized trust
[cite_start]anchors[cite: 22, 23]. ACE-GF addresses these challenges
by decoupling deterministic identity from long-term secret
[cite_start]storage[cite: 25].

## Core Contributions

ACE-GF introduces a generative framework for Atomic
Cryptographic Entities (ACE) with the following properties:

* **Seed-Storage-Free**: The identity root (REV) exists only
[cite_start]ephemerally in memory[cite: 29].
* **Deterministic Reconstruction**: The REV is reconstructed
[cite_start]from a sealed artifact and authorization credentials[cite: 30].
* **Context Isolation**: Cryptographic keys are isolated
across algorithms (e.g., Ed25519, PQC) using explicit
[cite_start]context encoding[cite: 33].

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY",
and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 [RFC2119] [RFC8174].

This document defines the following core terms:

* **ACE (Atomic Cryptographic Entity)**: A digital identity
represented by a stable entropy source that is
not stored in persistent plaintext.
* **REV (Root Entropy Value)**: A 256-bit high-entropy
secret used as the foundation of an ACE's identity.
It MUST remain ephemeral in memory.
* **SA (Sealed Artifact)**: An encrypted blob containing
the REV, protected by the Authorization Pipeline.
* **Cred (Authorization Credential)**: A user-provided
secret (e.g., password or biometric-derived entropy)
used to unlock the SA.
* **Context (Ctx)**: A tuple consisting of (AlgID, Domain, Index)
used to ensure cryptographic isolation between derived keys.

# Architecture and Design Principles

ACE-GF separates the identity lifecycle into two distinct pipelines:

## Identity Pipeline
The identity pipeline manages the transformation from the REV to
application-specific keys. It utilizes a deterministic, one-way
derivation function (HKDF) combined with explicit context strings.
This ensures that compromise of a specific child key (e.g., an
Ed25519 signing key) does not leak information about the REV or
other sibling keys.

## Authorization Pipeline
The authorization pipeline manages the secure "sealing" and
"unsealing" of the REV. By utilizing Argon2id for memory-hard
key stretching and AES-GCM-SIV for nonce-misuse resistant
encryption, the framework ensures that the REV is only
accessible when the correct Credential is provided.

# Cryptographic Primitives

The ACE-GF framework relies on industry-proven cryptographic primitives.
Implementations MUST strictly adhere to the selection of these primitives
to ensure deterministic consistency across different platforms and
environments.

## KDF1: Credential Hashing (Argon2id)

To resist offline brute-force attacks, ACE-GF utilizes the Argon2id
algorithm [RFC9106] for stretching user-provided credentials (Cred) into
a symmetric sealing key (K_seal).

* **Algorithm Selection**: Implementations MUST use the Argon2id variant
(as opposed to Argon2i or Argon2d) to provide optimized protection
against both side-channel attacks and GPU-based cracking.
* **Parameter Negotiation**: Implementations SHOULD support pre-defined
Sealing Profiles that specify memory cost (M), time iterations (T),
and parallelism (P).
* **Salt**: Each Sealed Artifact (SA) MUST include a unique 128-bit
random salt to ensure that identical credentials result in unique
sealing keys.

## AEAD: Sealing Encryption (AES-GCM-SIV)

ACE-GF employs AES-GCM-SIV [RFC8452] for the authenticated encryption
of the Root Entropy Value (REV).

* **Misuse Resistance**: AES-GCM-SIV is selected for its Synthetic
Initialization Vector (SIV) properties. In the specific context of
ACE-GF, given that the REV is a 256-bit high-entropy random value,
using a fixed 96-bit all-zero nonce (N_fixed) is mathematically
secure.
* **Security Assurance**: The use of AES-GCM-SIV prevents confidentiality
leaks even in cases of nonce reuse, eliminating the dependency on
high-fidelity hardware Random Number Generators (RNG) during every
sealing operation.
* **Data Structure**: The encryption process MUST produce a 256-bit
ciphertext and a 128-bit authentication tag.

## KDF2: Key Derivation (HKDF-SHA256)

For deriving algorithm-specific keys from the REV, ACE-GF utilizes
HKDF [RFC5869].

* **Core Logic**: The standard Extract-then-Expand workflow is followed.
* **Extract**: Map the REV into a cryptographically strong
Pseudorandom Key (PRK).
* **Expand**: Input the structured Context tuple (Ctx) as the
'info' parameter to generate target keys of specific lengths.
* **Hash Function**: SHA-256 MUST be used.
* **Isolation Guarantee**: By explicitly encoding AlgID, Domain, and
Index into the 'info' string, HKDF ensures that the resulting
child keys are computationally independent.

# Protocol Specification

This section defines the operational procedures for the ACE-GF framework.
All cryptographic operations MUST follow the sequences described herein
to maintain cross-platform interoperability.

## Root Entropy Value (REV) Generation

The Root Entropy Value (REV) serves as the atomic foundation of an
Identity.

1.  The REV MUST be a 256-bit (32-byte) value.
2.  The REV MUST be sampled from a cryptographically secure random
number generator (CSPRNG) with uniform distribution.
3.  The REV MUST NOT be stored in persistent storage in its raw form.
It MUST only exist in volatile memory during active use and SHOULD
be zeroized immediately after the Sealing or Derivation process.

## Sealing Process (Seal)

The Sealing process transforms the REV into a persistent Sealed
Artifact (SA) using an Authorization Credential.

### Sealing Key Derivation (K_seal)

To derive the symmetric sealing key:
1.  Generate or retrieve a 128-bit random Salt.
2.  Input the user Credential, Salt, and selected Sealing Profile
parameters into the Argon2id function.
3.  The output MUST be a 256-bit key, designated as K_seal.

### Deterministic Encryption Steps (N_fixed)

Once K_seal is derived, the REV is encrypted as follows:
1.  **Algorithm**: AES-256-GCM-SIV.
2.  **Nonce (N_fixed)**: A fixed 96-bit (12-byte) all-zero value.
The use of a fixed nonce is permitted here because the REV
itself provides the necessary entropy for the SIV construction.
3.  **Operation**: Encrypt the REV using K_seal and N_fixed.
4.  **Output**: A 256-bit Ciphertext and a 128-bit Authentication Tag.

The resulting **Sealed Artifact (SA)** is the concatenation of:
`Version || ProfileID || Salt || Ciphertext || Tag`

## Unsealing Process (Unseal)

The Unsealing process reconstructs the REV from a provided SA and Credential.

1.  **Parse**: Extract the Version, ProfileID, Salt, Ciphertext, and
Tag from the SA.
2.  **Derive**: Recompute K_seal using the Credential, Salt, and the
parameters defined by the ProfileID.
3.  **Decrypt**: Execute AES-256-GCM-SIV decryption on the Ciphertext
using K_seal, N_fixed, and the Tag.
4.  **Failure Handling**: If the authentication tag verification fails,
the implementation MUST return an error and MUST NOT release any
part of the decrypted data. The process SHOULD include a
protection mechanism against timing attacks.

## Key Derivation Function (Derive)

The Derive function generates application-specific keys from the REV.

### Context Tuple Structure

To ensure deterministic and isolated derivation, a structured
**Context Tuple (Ctx)** is defined:

* **AlgID (16-bit)**: Identifies the target algorithm (e.g., Ed25519).
* **Domain (8-bit)**: Specifies the usage domain (e.g., 0x01 for
Signing, 0x02 for Encryption).
* **Index (32-bit)**: An incremental counter allowing for
virtually unlimited keys per algorithm/domain.

The Ctx MUST be serialized into a consistent byte string before
being used as the 'info' parameter in HKDF.

### Computational Independence Guarantee

The derivation follows the HKDF-SHA256 Extract-and-Expand logic:
1.  `PRK = HKDF-Extract(Salt=0, IKM=REV)`
2.  `DerivedKey = HKDF-Expand(PRK, info=Ctx, L=KeyLength)`

By including the AlgID and Domain in the 'info' parameter, the
framework guarantees that a compromise of one DerivedKey provides
no computational advantage in recovering the REV or any other
DerivedKey associated with a different Ctx.

# Data Structures and Encodings

## Sealed Artifact (SA) Binary Format

The Sealed Artifact (SA) is a serialized byte array that contains all necessary
metadata and encrypted data to reconstruct the Identity. All multi-byte
fields MUST be encoded in Big-Endian (Network Byte Order).

The SA structure is defined as follows:

| Offset | Length | Field         | Description                          |
|--------|--------|---------------|--------------------------------------|
| 0      | 4      | Magic Number  | Fixed bytes: 0x41 0x43 0x45 0x00 ('ACE\0') |
| 4      | 1      | Version       | Protocol version (currently 0x01)    |
| 5      | 1      | Profile ID    | Identifier for Sealing Profile       |
| 6      | 16     | Salt          | Random salt for Argon2id             |
| 22     | 32     | Ciphertext    | AES-GCM-SIV encrypted REV            |
| 54     | 16     | Tag           | Authentication Tag (MAC)             |

**Total Length: 70 Bytes.**

## Sealing Profiles

Sealing Profiles define the cost parameters for the Argon2id function. This
allows ACE-GF to scale from resource-constrained mobile devices to
high-security server environments.

| Profile ID | Label    | Memory (MiB) | Iterations (T) | Parallelism (P) |
|------------|----------|--------------|----------------|-----------------|
| 0x01       | Mobile   | 64           | 3              | 1               |
| 0x02       | Standard | 256          | 4              | 2               |
| 0x03       | Paranoid | 1024         | 8              | 4               |

Implementations MUST support at least the 'Standard' (0x02) profile. The
'Paranoid' profile is RECOMMENDED for high-value administrative identities.

## Context Labels

To ensure computational independence between different cryptographic algorithms,
the `AlgID` field in the Context Tuple MUST use the following initial
registry. This ensures that a key derived for Ed25519 cannot be mistakenly
used or mathematically linked to a Secp256k1 key.

### Algorithm Identifiers (AlgID)

| AlgID  | Algorithm Name       | Reference |
|--------|----------------------|-----------|
| 0x01   | Ed25519              | RFC 8032  |
| 0x02   | Secp256k1 (ECDSA)    | SEC 2     |
| 0x03   | X25519 (Diffie-Hellman)| RFC 7748  |
| 0x04   | AES-256-GCM (Symmetric)| NIST SP800-38D |
| 0x05   | ML-DSA (Dilithium-PQC)| FIPS 204  |
| 0x06   | ML-KEM (Kyber-PQC)   | FIPS 203  |

### Usage Domains (Domain)

The 8-bit Domain field separates keys by their functional intent:

* **0x01 (Signing)**: Primary identity signatures.
* **0x02 (Encryption)**: Data at rest or in transit.
* **0x03 (Authentication)**: Challenge-response protocols.
* **0x04 (Key Wrapping)**: Protecting other sub-keys.

# Identity Lifecycle Operations

One of the primary advantages of the ACE-GF framework is its ability to manage
the identity lifecycle without requiring changes to the underlying root
entropy. This section defines the procedures for credential management and
migration.

## Stateless Credential Rotation

Stateless Credential Rotation allows an entity to update its Authorization
Credential (e.g., changing a password) without altering the Root Entropy
Value (REV). Because the REV is the source of all derived keys, this
process ensures that the ACE's identity and all its associated cryptographic
keys remain stable.

The rotation process is performed as follows:
1.  **Unseal**: Use the current Credential and the existing Sealed
Artifact (SA) to reconstruct the REV in volatile memory.
2.  **Generate New Salt**: Sample a new 128-bit random Salt.
3.  **Re-Seal**: Perform the Sealing Process (as defined in Section 4.2)
using the *new* Credential and the *new* Salt, while maintaining the
*same* REV.
4.  **Commit**: Replace the old SA with the newly generated SA.

This operation is "stateless" from the perspective of the identity
foundation; no derived keys (e.g., blockchain addresses or SSH keys)
need to be updated or re-announced to the network.

## Authorization-Bound Revocation

ACE-GF supports a unique mechanism for immediate revocation by decoupling
the components required for REV reconstruction.

In high-security deployments, the Authorization Pipeline can be distributed
across multiple components (e.g., a user-held password and a server-held
secret).

1.  **Revocation by Destruction**: To revoke access to an ACE, the
controlling entity simply destroys the associated Sealed Artifact (SA)
or the server-held component of the Credential.
2.  **Immediate Effect**: Without the SA or the specific Credential salt,
the REV becomes mathematically unreachable.
3.  **No CRL/OCSP Required**: Unlike traditional certificate-based
revocation, this is an inherent cryptographic lock. Once the "pathway"
to the REV is broken, the identity is effectively offline until a
backup SA (if any) is deployed.

## Legacy Key Migration (Optional)

To facilitate the adoption of ACE-GF by existing systems, it is possible
to "wrap" legacy private keys into the framework.

Instead of generating a random 256-bit REV as described in Section 4.1,
an implementation MAY:
1.  Take an existing high-entropy private key (the "Legacy Key").
2.  Treat this Legacy Key as the REV.
3.  Proceed with the Sealing Process (Section 4.2) to create an SA.

This allows the legacy key to benefit from the "Seed-Storage-Free"
properties of ACE-GF. However, implementations SHOULD note that keys
imported this way might not follow the strict context-isolation
properties defined for native ACE-GF derived keys.

# Security Considerations

The security of the ACE-GF framework depends on the strength of the underlying
cryptographic primitives and the rigor of the implementation environment.

## Entropy Requirements for Credentials

The security of the Sealed Artifact (SA) is directly proportional to the
entropy of the Authorization Credential (Cred).

1.  **Minimum Entropy**: Credentials SHOULD possess at least 128 bits of
entropy to resist sophisticated offline attacks.
2.  **Entropy Stretching**: While Argon2id provides significant resistance
against brute-force, it cannot compensate for extremely weak secrets
(e.g., short, common passwords).
3.  **Machine-Generated Credentials**: For Autonomous Digital Entities (ADEs),
credentials MUST be generated using a CSPRNG.

## Side-Channel Protections and Memory Management

Since the Root Entropy Value (REV) is the "single source of truth" for the
entire identity, its exposure in volatile memory must be strictly controlled.

### Trusted Execution Environments (TEE)
Implementations are STRONGLY RECOMMENDED to perform the Unsealing and
Derivation processes within a hardware-isolated Trusted Execution
Environment (e.g., Intel SGX, ARM TrustZone, or AWS Nitro Enclaves).
This ensures that even a compromised host OS cannot observe the REV or
the intermediate Sealing Key (K_seal).

### Memory Zeroization
To prevent "cold boot" attacks or memory forensics, implementations MUST
ensure that:
1.  All memory buffers containing the REV, K_seal, or raw Credentials
are overwritten with zeros (Zeroization) immediately after use.
2.  Memory pages used for these secrets SHOULD be marked as non-swappable
(e.g., using `mlock` on POSIX systems) to prevent sensitive data
from being written to a persistent swap file.

## Resistance to Brute-Force Attacks

The use of Argon2id allows ACE-GF to scale its defense according to the
threat model. The following table provides a theoretical analysis of
attack costs across different Profiles:

| Profile | Target Device | Attacker Cost Assumption (Memory-Hardness) |
|---------|---------------|--------------------------------------------|
| Mobile  | Low-Power IoT | Balanced for battery life; vulnerable to high-end GPU clusters. |
| Standard| Desktop/Web   | Resistant to mid-scale commodity GPU attacks. |
| Paranoid| Server/HSM    | Prohibitively expensive for all but state-actor level adversaries due to high memory bandwidth requirements (1GB+ per attempt). |

## Post-Quantum Transition and Hybrid Security

ACE-GF is designed with "Algorithm Agility" to survive the transition to
Post-Quantum Cryptography (PQC).

1.  **Context-Isolated PQC**: As defined in Section 5.3, the framework
allows the derivation of PQC keys (e.g., ML-DSA) alongside classical
keys (e.g., Ed25519) from the same REV.
2.  **Hybrid Derivation**: For maximum security during the transition
period, implementations MAY use a hybrid approach where a classical
signature and a PQC signature are required to authorize a single
action.
3.  **Future-Proofing REV**: Because the REV is a high-entropy (256-bit)
random value, it is considered "Quantum-Safe" against Grover's
algorithm, providing a 128-bit security margin even in a
post-quantum world.

## Note on AES-GCM-SIV and Fixed Nonce

The use of a fixed all-zero nonce (N_fixed) in Section 4.2.2 is safe
specifically because the plaintext being encrypted (the REV) is
guaranteed to be a unique, high-entropy 256-bit value for every
Sealed Artifact. Therefore, the SIV (Synthetic Initialization Vector)
derivation will inherently produce unique sub-keys for the underlying
CTR mode, preventing the catastrophic key-stream reuse associated
with standard AES-GCM.

# IANA Considerations

This document requests IANA to create two new registries for the Atomic
Cryptographic Entity Generative Framework (ACE-GF).

## ACE-GF Sealing Profile Registry

IANA is requested to create a new registry entitled "ACE-GF Sealing
Profiles". This registry manages the parameter sets for the credential
hashing function (Argon2id).

The registration policy for this registry is "Specification Required"
as defined in [RFC8126].

Initial entries for this registry are as follows:

| Profile ID | Label    | Memory (MiB) | Iterations (T) | Parallelism (P) | Reference |
|------------|----------|--------------|----------------|-----------------|-----------|
| 0x01       | Mobile   | 64           | 3              | 1               | [This RFC]|
| 0x02       | Standard | 256          | 4              | 2               | [This RFC]|
| 0x03       | Paranoid | 1024         | 8              | 4               | [This RFC]|
| 0x04-0xFF  | Unassigned|             |                |                 |           |

## ACE-GF Context Identifier Registry

IANA is requested to create a new registry entitled "ACE-GF Context
Identifiers". This registry manages the Algorithm Identifiers (AlgID)
used in the key derivation context string.

The registration policy for this registry is "Expert Review" as defined
in [RFC8126].

Initial entries for this registry are as follows:

| AlgID     | Algorithm Name          | Reference |
|-----------|-------------------------|-----------|
| 0x0001    | Ed25519                 | RFC 8032  |
| 0x0002    | Secp256k1               | SEC 2     |
| 0x0003    | X25519                  | RFC 7748  |
| 0x0004    | AES-256-GCM             | NIST SP800-38D |
| 0x0005    | ML-DSA (Dilithium)      | FIPS 204  |
| 0x0006    | ML-KEM (Kyber)          | FIPS 203  |
| 0x0007-0xFFFF | Unassigned          |           |

## ACE-GF Usage Domain Registry

IANA is requested to create a new registry entitled "ACE-GF Usage Domains".
This registry manages the 8-bit Domain field.

| Domain ID | Description             | Reference |
|-----------|-------------------------|-----------|
| 0x01      | Signing                 | [This RFC]|
| 0x02      | Encryption              | [This RFC]|
| 0x03      | Authentication          | [This RFC]|
| 0x04      | Key Wrapping            | [This RFC]|
| 0x05-0xFF | Unassigned              |           |

# Test Vectors

This section provides test vectors for developers to verify their
implementations of ACE-GF. All hexadecimal values are represented
without the '0x' prefix.

## Basic Test Vector (Standard Profile)

This test case uses the "Standard" Sealing Profile (0x02).

* **Credential**: "password123"
* **Salt**: 0102030405060708090a0b0c0d0e0f10
* **Argon2id Parameters**: M=256MiB, T=4, P=2
* **REV**:
f0e1d2c3b4a5968778695a4b3c2d1e0f00112233445566778899aabbccddeeff

**Output - Sealed Artifact (SA)**:
41434500 (Magic)
01       (Version)
02       (ProfileID)
0102030405060708090a0b0c0d0e0f10 (Salt)
[Insert 32-byte Hex Ciphertext here]
[Insert 16-byte Hex Tag here]

## Cross-Platform Consistency (UTF-8 Credentials)

This test case ensures that non-ASCII credentials are handled
consistently using UTF-8 encoding before the Argon2id process.

* **Credential**: "密码123" (UTF-8: e5af86e7a081313233)
* **Salt**: f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
* **ProfileID**: 0x01 (Mobile)

**Output - Reconstructed REV**:
[Insert 32-byte Hex REV here]

## Multi-Algorithm Derivation (ECC + PQC)

This test case demonstrates the generative nature of the framework by
deriving keys for both classical and post-quantum algorithms from
the same REV.

* **REV**:
603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4

### Case A: Ed25519 Signing Key
* **AlgID**: 0x0001
* **Domain**: 0x01
* **Index**: 0
* **Context Info (Hex)**: 00010100000000
* **Derived Key (32 bytes)**:
[Insert Hex Key here]

### Case B: ML-KEM (Kyber) Key
* **AlgID**: 0x0006
* **Domain**: 0x02
* **Index**: 0
* **Context Info (Hex)**: 00060200000000
* **Derived Key (64 bytes)**:
[Insert Hex Key here]

# References

## Normative References

[RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997.

[RFC8174]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174, May 2017.

[RFC5869]  Krawczyk, H. and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)", RFC 5869, DOI 10.17487/RFC5869, May 2010.

[RFC8452]  Gueron, S., Langley, A., and Y. Lindell, "AES-GCM-SIV: Nonce-Misuse-Resistant Authenticated Encryption", RFC 8452, DOI 10.17487/RFC8452, April 2018.

[RFC9106]  Biryukov, A., Dinu, D., and D. Khovratovich, "Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications", RFC 9106, DOI 10.17487/RFC9106, September 2021.

[FIPS204]  NIST, "Module-Lattice-Based Digital Signature Standard", FIPS PUB 204, August 2024.

## Informative References

[RFC8032]  Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, DOI 10.17487/RFC8032, January 2017.

[SEC2]     Certicom Research, "SEC 2: Recommended Elliptic Curve Domain Parameters", Version 2.0, January 2010.

[BIP32]    Wuille, P., "Hierarchical Deterministic Wallets", February 2012.

--- back

# Appendix A. Implementation Considerations for Resource-Constrained Devices

For IoT devices with limited RAM that cannot support the 'Standard' Argon2id
profile (256 MiB), the following optimizations are RECOMMENDED:

1.  **Offloading Sealing**: The Sealing process can be performed on a
provisioning terminal. The device only needs to store the resulting
Sealed Artifact (SA).
2.  **Unsealing via TEE**: If the device features a Secure Element (SE) or
TEE, the K_seal derivation SHOULD be pinned to the hardware UID to
provide an additional layer of security even if the Credential is weak.

# Appendix B. Python Reference Implementation

A simplified reference implementation of the ACE-GF derivation logic:

```python
import hashlib
import hmac

def hkdf_expand(prk, info, length):
    t = b""
    okm = b""
    for i in range((length + 31) // 32):
        t = hmac.new(prk, t + info + bytes([i + 1]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

# Example Context Construction
alg_id = (1).to_bytes(2, 'big')   # Ed25519
domain = (1).to_bytes(1, 'big')   # Signing
index  = (0).to_bytes(4, 'big')   # Index 0
ctx_info = alg_id + domain + index

# prk = hkdf_extract(salt=0, ikm=REV)
# derived_key = hkdf_expand(prk, ctx_info, 32)

--- back

# Acknowledgments
{:numbered="false"}

The author would like to thank the members of the IETF Security Area
for their initial feedback and review of this generative framework.

