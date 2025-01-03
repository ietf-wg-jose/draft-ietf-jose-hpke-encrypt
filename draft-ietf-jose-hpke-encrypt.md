---
title: "Use of Hybrid Public Key Encryption (HPKE) with JSON Object Signing and Encryption (JOSE)"
abbrev: "Use of HPKE in JOSE"
category: std

docname: draft-ietf-jose-hpke-encrypt-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "JOSE"
keyword:
 - HPKE
 - JOSE
 - PQC
 - Hybrid

venue:
  group: "jose"
  type: "Working Group"
  mail: "jose@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/jose/"


stand_alone: yes
pi: [toc, sortrefs, symrefs, strict, comments, docmapping]

author:
 -
    fullname: Tirumaleswar Reddy
    organization: Nokia
    city: Bangalore
    region: Karnataka
    country: India
    email: "kondtir@gmail.com"

 -
    fullname: Hannes Tschofenig
    organization: University of Applied Sciences Bonn-Rhein-Sieg
    abbrev: H-BRS
    country: Germany
    email: "hannes.tschofenig@gmx.net"

 -
    fullname: Aritra Banerjee
    organization: Nokia
    city: Munich
    country: Germany
    email: "aritra.banerjee@nokia.com"

 -
    ins: O. Steele
    name: Orie Steele
    organization: Transmute
    email: orie@transmute.industries
    country: United States

 -
    ins: M. Jones
    name: Michael B. Jones
    organization: Self-Issued Consulting
    email: michael_b_jones@hotmail.com
    uri: https://self-issued.info/
    country: United States

normative:
  RFC2119:
  RFC8174:
  RFC9180:
  RFC7516:
  RFC7517:
  RFC8725:
  JOSE-IANA:
     author:
        org: IANA
     title: JSON Web Signature and Encryption Algorithms
     target: https://www.iana.org/assignments/jose/jose.xhtml

informative:
  RFC8937:

  HPKE-IANA:
     author:
        org: IANA
     title: Hybrid Public Key Encryption (HPKE) IANA Registry
     target: https://www.iana.org/assignments/hpke/hpke.xhtml
     date: October 2023
---


--- abstract


This specification defines Hybrid Public Key Encryption (HPKE) for use with
JSON Object Signing and Encryption (JOSE). HPKE offers a variant of
public key encryption of arbitrary-sized plaintexts for a recipient public key.

HPKE works for any combination of an asymmetric key encapsulation mechanism (KEM),
key derivation function (KDF), and authenticated encryption with additional data
(AEAD) function. Authentication for HPKE in JOSE is provided by
JOSE-native security mechanisms or by one of the authenticated variants of HPKE.

This document defines the use of the HPKE with JOSE.

--- middle

# Introduction

Hybrid Public Key Encryption (HPKE) {{RFC9180}} is a scheme that
provides public key encryption of arbitrary-sized plaintexts given a
recipient's public key.

This specification enables JSON Web Encryption (JWE) to leverage HPKE,
bringing support for KEMs and the possibility of Post Quantum or Hybrid KEMs to JWE.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Conventions and Terminology

This specification uses the following abbreviations and terms:

- Content Encryption Key (CEK), is defined in {{RFC7517}}.
- Hybrid Public Key Encryption (HPKE) is defined in {{RFC9180}}.
- pkR is the public key of the recipient, as defined in {{RFC9180}}.
- skR is the private key of the recipient, as defined in {{RFC9180}}.
- Key Encapsulation Mechanism (KEM), see {{RFC9180}}.
- Key Derivation Function (KDF), see {{RFC9180}}.
- Authenticated Encryption with Associated Data (AEAD), see {{RFC9180}}.
- Additional Authenticated Data (AAD), see {{RFC9180}}.

# JOSE-HPKE

This document specifies two modes for JOSE-HPKE:

  *  HPKE JWE Integrated Encryption, where HPKE is used to directly encrypt the plaintext.
  *  Key Encryption, where HPKE is used to encrypt a content encryption key (CEK) for encrypting the plaintext.

When "alg" is a JOSE-HPKE algorithm:

  * If "enc" is "dir", HPKE JWE Integrated Encryption is used.
  * If "enc" is an AEAD algorithm, The recipient Key Managment mode is Key Encryption.

The HPKE KEM, KDF and AEAD used depend on the JOSE-HPKE algorithm used.

HPKE supports several modes, which are described in Table 1 of {{RFC9180}}.

The HPKE mode used is determined by header parameters "psk_id" and "auth_kid" in the JOSE Header:

  * If neither is present, base mode is used.
  * If only "psk_id" is present, PSK mode is used.
  * If only "auth_kid" is present,  Auth mode is used.
  * If both are present, AuthPSK mode is used.

If authentication is not supported by the HPKE KEM used, the "auth_kid" header parameter MUST be absent.


## HPKE JWE Integrated Encryption

When encrypting, the inputs to HPKE Seal operation are set as follows:

- kem_id: Depends on the JOSE-HPKE algorithm used.
- pkR: The recipient public key, converted into HPKE public key.
- kdf_id: Depends on the JOSE-HPKE algorithm used.
- aead_id: Depends on the JOSE-HPKE algorithm used.
- info: By default, an empty string. Application MAY specify some other value.
- aad: Additional Authenticated Data encryption parameter defined in {{RFC7516}} section 5.1 step 14.
- pt: The message plaintext, compressed using the algorithm in "zip" header parameter if present.

Additionally, if the "psk_id" header parameter is present:

- psk: The pre-shared key.
- psk_id: The value of the "psk_id" header parameter.

Additionally, if the "auth_kid" header parameter is present:

- skS: The sender private key, converted into HPKE private key.

The resulting JWE is filled as follows:

- JWE Protected Header:
  * MUST contain "enc" with value "dir"
  * MUST contain "alg" that is the used JOSE-HPKE algorithm.
  * MUST contain the "apu", "apv" and "zip" header parameters, if present.
- JWE Initialization Vector MUST be empty.
- JWE Ciphertext MUST be the raw ct output from HPKE Seal operation.
- JWE Authentication Tag MUST be empty.
- There MUST be exactly one recipient, with:
  * JWE Per-Recipient Unprotected Header MUST be empty.
  * JWE Encrypted Key MUST contain the raw enc output from HPKE Seal operation.

The "ek" header parameter MUST NOT be present.

When decrypting, the inputs to HPKE Open operation are set as follows:

- kem_id: Depends on the JOSE-HPKE algorithm used.
- skR: The recipient private key, converted into HPKE private key.
- kdf_id: Depends on the JOSE-HPKE algorithm used.
- aead_id: Depends on the JOSE-HPKE algorithm used.
- info: By default, an empty string. Application MAY specify some other value.
- add: Additional Authenticated Data encryption parameter defined in {{RFC7516}} section 5.2. step 15.
- enc: The JWE Encrypted Key of the sole recipient.
- ct: The JWE Ciphertext.

Additionally, if the "psk_id" header parameter is present:

- psk: The pre-shared key.
- psk_id: The value of the "psk_id" header parameter.

Additionally, if the "auth_kid" header parameter is present:

- pkS: The sender public key, converted into HPKE public key.

If the "zip" header parameter is present, the resulting plaintext is uncompressed using the algorithm specified and the result is the
raw message plaintext. Otherwise the resulting plaintext is the raw message plaintext.

When decrypting, the checks in {{RFC7516}} section 5.2. steps 1 through 5 MUST be performed.

## Key Encryption

The Recipient Context is defined as follows:

`len32(enc)||enc||len32(apu)||apu||len32(apv)||apv`

Where:

 - `×||y` is the concatenation of byte strings x and y.
 - len32(x) is number of bytes in x as four-byte big-endian integer.
 - enc is the value of "enc" header parameter in JOSE header. The integrity-protected 'enc' parameter provides protection against an
   attacker who manipulates the encryption algorithm in the 'enc' parameter.
 - apu is The value of "apu" header parameter if present in JOSE header, otherwise empty string.
 - apv is The value of "apv" header parameter if present in JOSE header, otherwise empty string.

 TBD: Authenticated key agreement mechanisms, such as ECDH-SS or authenticated HPKE modes, mitigate the risk of misusing apu and apv by binding the derived key to the specific identities of the participants. This ensures that any alteration to apu or apv invalidates the derived key, preventing unintended use. However, in the base mode of HPKE, where no authentication is provided, the use of apu and apv does not offer any security guarantees and could be subject to misuse. Do we really need apu and apv in the Recipient Context and why is it not required for JWE Integrated Encryption ?

The "auth_kid" header parameter MUST NOT be present in JOSE header.

When encrypting, the inputs to HPKE Seal operation are set as follows:

- kem_id: Depends on the JOSE-HPKE algorithm used.
- pkR: The recipient public key, converted into HPKE public key.
- kdf_id: Depends on the JOSE-HPKE algorithm used.
- aead_id: Depends on the JOSE-HPKE algorithm used.
- info: By default, an empty string. Application MAY specify some other value.
TBD: The existing JWE specifications do not provide a mechanism to include application context as AAD. Addressing this limitation exclusively for HPKE, while not applying similar measures to other algorithms, introduces an asymmetry in how messages are bound to their origin. This inconsistency could create potential vulnerabilities by differing security assurances across cryptographic algorithms. Why is this required just for JWE HPKE ?
- aad: The Recipient Context.
- pt: The CEK.

Additionally, if the "psk_id" header parameter is present:

- psk: The pre-shared key.
- psk_id: The value of the "psk_id" header parameter.

The outputs are used as follows:

- enc: MUST be placed base64url-encoded in "ek" header parameter in JOSE header.
- ct: MUST be placed raw in recpient JWE Encrypted Key.

When decrypting, the inputs to HPKE Open operation are set as follows:

- kem_id: Depends on the JOSE-HPKE algorithm used.
- skR: The recipient private key, converted into HPKE private key.
- kdf_id: Depends on the JOSE-HPKE algorithm used.
- aead_id: Depends on the JOSE-HPKE algorithm used.
- info: By default, an empty string. Application MAY specify some other value.
- add: The Recipient Context.
- enc: The base64url-decoded value of the "ek" header parameter in JOSE header.
- ct: The JWE Encrypted Key of the recipient.

Additionally, if the "psk_id" header parameter is present in JOSE header:

- psk: The pre-shared key.
- psk_id: The value of the "psk_id" header parameter.

The resulting plaintext is the CEK.

## Keys

JWKs can be used to to represent KEM private or public keys. When using JWK for JOSE-HPKE, the following checks are made:

* If the "kty" field is "AKP", then the public and private keys MUST be raw HPKE public and private
keys (respectively) for the KEM used by the algorithm.
* Otherwise, the key MUST be suitable for the KEM used by the algorithm. In case the "kty" parameter
is "EC" or "OKP", this means the value of "crv" parameter is suitable. For the algorithms defined in
this document, the valid combinations of the KEM, "kty" and "crv" are shown in  {{ciphersuite-kty-crv}}.

~~~
+---------------------+-----------------+
| HPKE KEM id         | JWK             |
|                     | kty | crv       |
+---------------------+-----+-----------+
| 0x0010, 0x0013      | EC  | P-256     |
| 0x0011, 0x0014      | EC  | P-384     |
| 0x0012, 0x0015      | EC  | P-521     |
| 0x0016              | EC  | secp256k1 |
| 0x0020              | OKP | X25519    |
| 0x0021              | OKP | X448      |
+---------------------+-----+-----------+
~~~
{: #ciphersuite-kty-crv title="JWK Types and Curves for JOSE-HPKE Ciphersuites"}


## Key Usage Guidelines for JOSE-HPKE

To ensure predictable key usage within JOSE-HPKE, the following restrictions and guidelines are introduced:

1. **New Key Use Values**
   The following values are registered in the "JSON Web Key Use" registry to explicitly identify the roles of keys in HPKE operations:
   - **HPKE-Sender:** A key intended for use in the sender role of HPKE operations, performing encryption and key encapsulation.
   - **HPKE-Receiver:** A key intended for use in the receiver role of HPKE operations, performing decryption and key decapsulation.

These values allow implementations to explicitly track and enforce role-specific key usage in HPKE operations and prevent key reuse with other cryptographic algorithms.

## Compact Example

A Compact JWE or JSON Web Token:

~~~
eyJhbGciOiJIUEtFLVAyNTYtU0hBMjU2LUExMjhHQ00iLCJlbmMiOiJkaXIiLCJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1icHJpbnQ6c2hhLTI1Njp2b2RIQ3FjVVdFbV83NUpWcXlhTjhaS1FVMjF3VEFSYzhkRzhuVU1jZlBVIn0.BCsvYxTHM4CO_OwQxL3lkJDdlw3UDjx2xN9MIXnbVzfTgFJmo_Es2xdH-fYs9EXfH_V53JgMWfUm7rBD_oE5efU..7_va6cnwClMsw7h7lqpm2tCrH9NkciM-g9UabdPWcOeIRmAf01NLYG7Wn8fFoohHlcGgd0nh7Jmo9nvHFi7sH6kOX7pplBnvLUoPrqeyW4TdXo_X8YThNKf9BFyWGyF6fjelbic5jSYClFaenMkTnjpHxFW1sWuiuZVmO1EOzrlNttWy.
~~~

After verification:

~~~
{
  "protectedHeader": {
    "alg": "HPKE-0",
    "enc": "dir",
    "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:vodHCqcUWEm_75JVqyaN8ZKQU21wTARc8dG8nUMcfPU"
  },
  "payload": {
    "urn:example:claim": true,
    "iss": "urn:example:issuer",
    "aud": "urn:example:audience",
    "iat": 1729785491,
    "exp": 1729792691
  }
}
~~~

## JSON Example

A JSON Encoded JWE:

~~~
{
  "protected": "eyJhbGciOiJIUEtFLVAyNTYtU0hBMjU2LUExMjhHQ00iLCJlbmMiOiJkaXIiLCJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1icHJpbnQ6c2hhLTI1NjpTNkFYZmRVXzZZZnp2dTBLRERKYjBzRnV3bklXUGs2TE1URXJZaFBiMzJzIiwicHNrX2lkIjoib3VyLXByZS1zaGFyZWQta2V5LWlkIiwiYXV0aF9raWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1icHJpbnQ6c2hhLTI1NjpTNkFYZmRVXzZZZnp2dTBLRERKYjBzRnV3bklXUGs2TE1URXJZaFBiMzJzIn0",
  "encrypted_key": "BD7QVodtG-FwYASgb36zuTzUCc80aiYwS6JOOE-6_heUGyAZt-cU0818e4oYqP7ebBuW3KTM9EQA0vM5fWp6hj0",
  "ciphertext": "ZxqtYoomgVQGctnv1I_EBVI1NIeJ7qJw2iVtqwUw3fXa8FK-",
  "aad": "8J-PtOKAjeKYoO-4jyBiZXdhcmUgdGhlIGFhZCE"
}
~~~

After verification:

~~~
{
  "protectedHeader": {
    "alg": "HPKE-0",
    "enc": "dir",
    "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:S6AXfdU_6Yfzvu0KDDJb0sFuwnIWPk6LMTErYhPb32s",
    "psk_id": "our-pre-shared-key-id",
    "auth_kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:S6AXfdU_6Yfzvu0KDDJb0sFuwnIWPk6LMTErYhPb32s"
  },
  "plaintext": "🖤 this plaintext!",
  "additionalAuthenticatedData": "🏴‍☠️ beware the aad!"
}
~~~

## Multiple Recipients example

For example:

~~~
{
  "protected": "eyJlbmMiOiJBMTI4R0NNIn0",
  "iv": "ZL0HDvZJizA6vyTV",
  "ciphertext": "Oq26x9vppULrGNzCn2jaB_Sl-Swjv7e0AcgnhUR5AtrjEf2v6jee09WN-Ne-HIGXBgQpgJPchg0eWNmgv4Ozi5I",
  "tag": "ULnlOiJRYfCzM_r5j9sLEQ",
  "aad": "cGF1bCBhdHJlaWRlcw",
  "recipients": [
    {
      "encrypted_key": "G3HmlpOgA4H1i_RQhT44Nw7svDwUqvNR",
      "header": {
        "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:cxQC_lWt22BIjH5AWSLHCZk_f-mU3-W4Ztcu5-ZbwTk",
        "alg": "ECDH-ES+A128KW",
        "epk": {
          "kty": "EC",
          "crv": "P-256",
          "x": "JnGWSQ90hlt0H7bfcgfaw2DZE-qqv_cwA4_Dn_CkLzE",
          "y": "6jw1AC5q9-qewwBh9DK5YzUHLOogToGDSpoYAJdNo-E"
        }
      }
    },
    {
      "encrypted_key": "pn6ED0ijngCiWF8Hd_PzTyayd2OmRF7QarTVfuWj6dw",
      "header": {
        "alg": "HPKE-0",
        "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:S6AXfdU_6Yfzvu0KDDJb0sFuwnIWPk6LMTErYhPb32s",
        "psk_id": "our-pre-shared-key-id",
        "auth_kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:S6AXfdU_6Yfzvu0KDDJb0sFuwnIWPk6LMTErYhPb32s",
        "ek": "BI41YDnhTTI6jSd7T62rLwzCCt_tBqN5LFooiZ7eXJsh01O0-h-BQ6JToKX9UXDw_3ylbXTiYWmPXl2fNmr4BeQ"
      }
    }
  ]
}
~~~

After verification:

~~~
{
  "plaintext": "🎵 My lungs taste the air of Time Blown past falling sands 🎵",
  "protectedHeader": {
    "enc": "A128GCM"
  },
  "unprotectedHeader": {
    "alg": "HPKE-0",
    "enc": "dir",
    "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:S6AXfdU_6Yfzvu0KDDJb0sFuwnIWPk6LMTErYhPb32s",
    "psk_id": "our-pre-shared-key-id",
    "auth_kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:S6AXfdU_6Yfzvu0KDDJb0sFuwnIWPk6LMTErYhPb32s",
    "ek": "BI41YDnhTTI6jSd7T62rLwzCCt_tBqN5LFooiZ7eXJsh01O0-h-BQ6JToKX9UXDw_3ylbXTiYWmPXl2fNmr4BeQ"
  },
  "additionalAuthenticatedData": "paul atreides"
}
~~~

# Security Considerations

This specification is based on HPKE and the security considerations of
{{RFC9180}} are therefore applicable also to this specification.

HPKE assumes the sender is in possession of the public key of the recipient and
HPKE JOSE makes the same assumptions. Hence, some form of public key distribution
mechanism is assumed to exist but outside the scope of this document.

HPKE in Base mode does not offer authentication as part of the HPKE KEM.
In this case JOSE constructs like JWS and JSON Web Tokens (JWTs) can be used to add authentication.
HPKE also offers modes that offer authentication.

HPKE relies on a source of randomness to be available on the device.
In Key Agreement with Key Wrapping mode, CEK has to be randomly generated and it MUST be ensured that the guidelines in {{RFC8937}} for random number generations are followed.

## HPKE authentication

Authenticated HPKE modes MUST NOT be used for Key Encryption, as the message is not authenticated. Any recipient could act as a man-in-the-middle (MitM) and modify the message.

## Key Management

A single key MUST NOT be used in both sender and recipient roles. Avoiding the use of the same key for both sender and recipient roles ensures clear cryptographic boundaries and minimizes unintended interactions.

A single key MUST NOT be used with both JOSE-HPKE and other algorithms as this might enable cross-protocol attacks.

The context binding performed by JOSE-HPKE and HPKE ensures that it is safe to use a single key with multiple JOSE-HPKE algorithms and for both Integrated Encryption and Key Encryption.

## Plaintext Compression

Implementers are advised to review Section 3.6 of {{RFC8725}}, which states:
Compression of data SHOULD NOT be done before encryption, because such compressed data often reveals information about the plaintext.

## Header Parameters

Implementers are advised to review Section 3.10 of {{RFC8725}}, which comments on application processing of JWE Protected Headers.
Additionally, Unprotected Headers can contain similar information which an attacker could leverage to mount denial of service, forgery or injection attacks.

## Ensure Cryptographic Keys Have Sufficient Entropy

Implementers are advised to review Section 3.5 of {{RFC8725}}, which provides comments on entropy requirements for keys.
This guidance is relevant to both public and private keys used in both Key Encryption and Integrated Encryption.
Additionally, this guidance is applicable to content encryption keys used in Key Encryption mode.

## Validate Cryptographic Inputs

Implementers are advised to review Section 3.4 of {{RFC8725}}, which provides comments on the validation of cryptographic inputs.
This guidance is relevant to both public and private keys used in both Key Encryption and Integrated Encryption, specifically focusing on the structure of the public and private keys.
These inputs are crucial for the HPKE KEM operations.

## Use Appropriate Algorithms

Implementers are advised to review Section 3.2 of {{RFC8725}}, which comments on the selection of appropriate algorithms.
This is guidance is relevant to both Key Encryption and Integrated Encryption.
When using Key Encryption, the strength of the content encryption algorithm should not be significantly different from the strengh of the Key Encryption algorithms used.

#  IANA Considerations {#IANA}

This document adds entries to {{JOSE-IANA}}.

## Updates to "JSON Web Key Use" Registry

The "JSON Web Key Use" registry is updated as follows:

   o  Use Member Value: "HPKE-Sender"
   o  Use Description: Key for HPKE sender role (encapsulation)
   o  Change Controller: IESG
   o  Specification Document(s): This document

   o  Use Member Value: "HPKE-Receiver"
   o  Use Description: Key for HPKE receiver role (decapsulation)
   o  Change Controller: IESG
   o  Specification Document(s): This document

## Ciphersuite Registration

This specification registers a number of JOSE-HPKE algorithms/ciphersuites.
A ciphersuite is a group of algorithms, often sharing component algorithms such as hash functions, targeting a security level.
A JOSE-HPKE algorithm is composed of the following choices:

- KEM Algorithm
- KDF Algorithm
- AEAD Algorithm

The "KEM", "KDF", and "AEAD" values are chosen from the HPKE IANA registry {{HPKE-IANA}}.

For readability the algorithm ciphersuites labels are built according to the following scheme:

~~~
HPKE-<KEM>-<KDF>-<AEAD>
~~~

Implementations detect the use of modes by inspecting header parameters.

## JSON Web Signature and Encryption Algorithms

The following entries are added to the "JSON Web Signature and Encryption Algorithms" registry:

### HPKE-0

- Algorithm Name: HPKE-0
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(P-256, HKDF-SHA256) KEM, the HKDF-SHA256 KDF and the AES-128-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s):   RFCXXXX
- Algorithm Analysis Documents(s): TODO

### HPKE-1

- Algorithm Name: HPKE-1
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(P-384, HKDF-SHA384) KEM, the HKDF-SHA384 KDF, and the AES-256-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s):   RFCXXXX
- Algorithm Analysis Documents(s): TODO

### HPKE-2

- Algorithm Name: HPKE-2
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(P-521, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the AES-256-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s):   RFCXXXX
- Algorithm Analysis Documents(s): TODO

### HPKE-3

- Algorithm Name: HPKE-3
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and the AES-128-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s):   RFCXXXX
- Algorithm Analysis Documents(s): TODO

### HPKE-4

- Algorithm Name: HPKE-4
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and the ChaCha20Poly1305 AEAD.
- Algorithm Usage Location(s): "alg, enc"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s):   RFCXXXX
- Algorithm Analysis Documents(s): TODO

### HPKE-5

- Algorithm Name: HPKE-5
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the AES-256-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s):   RFCXXXX
- Algorithm Analysis Documents(s): TODO

### HPKE-6

- Algorithm Name: HPKE-6
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the ChaCha20Poly1305 AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s):   RFCXXXX
- Algorithm Analysis Documents(s): TODO

## JSON Web Signature and Encryption Header Parameters

The following entries are added to the "JSON Web Key Parameters" registry:

### ek

- Header Parameter Name: "ek"
- Header Parameter Description: An encapsulated key as defined in { Section 5.1.1 of RFC9180 }
- Header Parameter Usage Location(s): JWE
- Change Controller: IETF
- Specification Document(s):   RFCXXXX

### psk_id

- Header Parameter Name: "psk_id"
- Header Parameter Description: A key identifier (kid) for the pre-shared key as defined in { Section 5.1.2 of RFC9180 }
- Header Parameter Usage Location(s): JWE
- Change Controller: IETF
- Specification Document(s):   RFCXXXX

### auth_kid

- Header Parameter Name: "auth_kid"
- Header Parameter Description: A key identifier (kid) for the asymmetric key as defined in { Section 5.1.3 of RFC9180 }
- Header Parameter Usage Location(s): JWE
- Change Controller: IETF
- Specification Document(s):   RFCXXXX

--- back

# Keys Used in Examples

This private key and its implied public key are used the examples:

~~~ text
{
  "kid": "S6AXfdU_6Yfzvu0KDDJb0sFuwnIWPk6LMTErYhPb32s",
  "alg": "HPKE-0",
  "kty": "EC",
  "crv": "P-256",
  "x": "wt36K06T4T4APWfGtioqDBXCvRN9evqkZjNydib9MaM",
  "y": "eupgedeE_HAmVJ62kpSt2_EOoXb6e0y2YF1JPlfr1-I",
  "d": "O3KznUTAxw-ov-9ZokwNaJ289RgP9VxQc7GJthaXzWY"
}
~~~

This pre-shared key is used in the examples:

~~~ text
{
  "kty": "oct",
  "kid": "our-pre-shared-key-id",
  "k": "anVnZW11anVnZW11Z29rb3Vub3N1cmlraXJla2FpamE"
}
~~~

# Acknowledgments
{: numbered="false"}

This specification leverages text from {{?I-D.ietf-cose-hpke}}.
We would like to thank
Matt Chanda,
Ilari Liusvaara,
Aaron Parecki,
and Filip Skokan
for their contributions to the specification.

# Document History
{: numbered="false"}

-04

* Fixed #8: Use short algorithm identifiers, per the JOSE naming conventions.

-01

* Apply feedback from call for adoption.
* Provide examples of auth and psk modes for JSON and Compact Serializations
* Simplify description of HPKE modes
* Adjust IANA registration requests
* Remove HPKE Mode from named algorithms
* Fix AEAD named algorithms

-00

* Created initial working group version from draft-rha-jose-hpke-encrypt-07
