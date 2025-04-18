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
  RFC7518:
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
(AEAD) function.

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

# Overview {#overview}

This specification describes two modes of use for HPKE in JWE:

  *  HPKE JWE Integrated Encryption, where HPKE is used to encrypt the plaintext.
  *  HPKE JWE Key Encryption, where HPKE is used to encrypt a content encryption key (CEK) and the CEK is subsequently used to encrypt the plaintext.

When "alg" is a JOSE-HPKE algorithm:

  * If "enc" is "int", HPKE JWE Integrated Encryption is used.
  * If "enc" is an AEAD algorithm, the recipient Key Managment mode is Key Encryption.

The HPKE KEM, KDF, and AEAD used depend on the JOSE-HPKE algorithm used.

HPKE supports several modes, which are described in Table 1 of {{RFC9180}}.

In JOSE-HPKE, only "mode_base" and "mode_psk" are supported.
When "psk_id" JOSE Header parameter is present the mode is "mode_psk", otherwise the mode is "mode_base".

JWE supports different serializations, including Compact JWE Serialization as described in Section 3.1 of {{RFC7516}}, General JWE JSON Serialization as described in Section 3.2 of {{RFC7516}}.

Certain JWE features are only supported in specific serializations.

For example Compact JWE Serialization does not support the following:

- additional authenticated data
- multiple recipients
- unprotected headers

HPKE JWE Key Encryption can be used with "aad" but only when not expressed with Compact JWE Serialization.

Single recipient HPKE JWE Key Encryption with no "aad" can be expressed in Compact JWE Serialization, so long as the recipient and sender use the same HPKE Setup process as described in { Section 5 of RFC9180 }.

## Auxiliary Authenticated Application Information

HPKE has two places at which applications can specify auxiliary authenticated information as described in { Section 8.1 of RFC9180 }.

HPKE algorithms are not required to process "apu" and "apv" as described in Section 4.6.1 of {{RFC7518}}, despite appearing to be similar to key agreement algorithms (such as "ECDH-ES").

The "aad parameter" for Open() and Seal() MUST be used with both HPKE JWE Integrated Encryption and HPKE JWE Key Encryption.

To avoid confusion between JWE AAD and HPKE AAD, this document uses the term "HPKE AEAD AAD" to refer the "aad parameter" for Open() and Seal().

## Encapsulated Keys {#encapsulated-keys}

HPKE encapsulated key is defined in Section 5.1.1 of {{RFC9180}}.

In HPKE JWE Integrated Encryption, the JWE Encrypted Key of the sole recipient is the HPKE encapsulated key.

In HPKE JWE Key Encryption, each recipient JWE Encrypted Key is the encrypted content encryption key, and the value of JOSE Header parameter "ek"
is base64url-encoded HPKE encapsulated key.

# Integrated Encryption

In HPKE JWE Integrated Encryption:

- The protected header MUST contain an "alg" that is JOSE-HPKE algorithm.
- The protected header MUST contain an "enc" with value "int". This is an explicit exception to requirement in Section 4.1.2 of {{RFC7516}} that
"enc" must be an AEAD algorithm. This is appropriate, as HPKE will perform plaintext encryption.
- The protected header parameters "psk_id" MAY be present.
- The protected header parameter "ek" MUST NOT be present.
- There MUST be exactly one recipient.
- The JWE Encrypted Key MUST be encapsulated key as defined in Section 5.1.1 of {{RFC9180}}.
- JWE Initialization Vector and JWE Authentication Tag MUST NOT be present.
- JWE AAD MAY be present.
- JWE Ciphertext is ciphertext as defined in Section 5.2 of {{RFC9180}}.
- The HPKE info parameter MUST be set to an empty string.
- The HPKE aad parameter MUST be set to the "JWE Additional Authenticated Data encryption parameter", as defined in Step 14 of Section 5.1 of {{RFC7516}}.
- If protected header contains the parameter "zip" (Section 4.1.3 of {{RFC7516}}), the plaintext is the message compressed with the indicated algorithm.
Otherwise, the plaintext is the raw message.


When decrypting, the checks in {{RFC7516}} section 5.2, steps 1 through 5 MUST be performed. The JWE Encrypted Key in step 2 is the
base64url encoded encapsulated key.

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
    "enc": "int",
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
    "enc": "int",
    "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:S6AXfdU_6Yfzvu0KDDJb0sFuwnIWPk6LMTErYhPb32s",
  },
  "plaintext": "🖤 this plaintext!",
  "additionalAuthenticatedData": "🏴‍☠️ beware the aad!"
}
~~~

# Key Encryption

Recipients using JOSE-HPKE can be added alongside other recpients (e.g., `ECDH-ES+A128KW` or `RSA-OAEP-384`), as HPKE is used to encrypt the
Content Encryption Key, which is then processed as specified in JWE.

The protected header used in content encryption is passed to HPKE as Additional Authenticated Data. The protected header encoding remains consistent
with existing JWE formatting rules.

In HPKE JWE Key Encryption:

- The Key Management Mode is Key Encryption.
- When all recipients use the same HPKE algorithm to secure the Content Encryption Key, the JWE Protected Header SHOULD contain "alg".
Otherwise, the JWE Protected Header (and JWE Shared Unprotected Header) MUST NOT contain "alg".
- JOSE Header parameter "alg" MUST be a JOSE-HPKE algorithm.
- JOSE Header parameter "psk_id" MAY be present.
- JOSE Header parameter "ek" MUST be present and contain base64url-encoded HPKE encapsulated key.
- Recipient JWE Encrypted Key MUST be the ciphertext from HPKE Encryption.
- The HPKE Setup info parameter MUST be set to an empty string.
- THE HPKE plaintext MUST be set to the CEK.

The processing of "enc", "iv", "tag", "aad", and "ciphertext" is already defined in {{RFC7516}}. Implementations should follow the existing
JWE specifications for handling these parameters, and no additional processing requirements are introduced by HPKE-based key encryption.

## Multiple Recipients Example

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
    "enc": "int",
    "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:S6AXfdU_6Yfzvu0KDDJb0sFuwnIWPk6LMTErYhPb32s",
    "ek": "BI41YDnhTTI6jSd7T62rLwzCCt_tBqN5LFooiZ7eXJsh01O0-h-BQ6JToKX9UXDw_3ylbXTiYWmPXl2fNmr4BeQ"
  },
  "additionalAuthenticatedData": "paul atreides"
}
~~~

# Mapping HPKE Keys to JWK for JOSE {#alg-mapping}

JWKs can be used to represent JOSE-HPKE private or public keys. For the algorithms defined in this document, the valid combinations of the
JWE Algorithm, "kty", and "crv" are shown in {{ciphersuite-kty-crv}}.

~~~
+---------------------+-----------------+
| JWE Algorithm       | JWK |           |
|                     | kty | crv       |
+---------------------+-----+-----------+
| HPKE-0 	      | EC  | P-256     |
| HPKE-1     	      | EC  | P-384     |
| HPKE-2              | EC  | P-521     |
| HPKE-3, HPKE-4      | OKP | X25519    |
| HPKE-5, HPKE-6      | OKP | X448      |
+---------------------+-----+-----------+
~~~
{: #ciphersuite-kty-crv title="JWK Types and Curves for JOSE-HPKE Ciphersuites"}

When the "kty" field is "AKP" and "alg" is a JOSE-HPKE algorithm, the public and private keys MUST be raw HPKE public and private keys (respectively)
for the KEM used by HPKE.


## JWK Representation of a JOSE-HPKE Key with HPKE Ciphersuite

An example is illustrated below for representing a JOSE-HPKE public/private keys.

~~~
{
  "kty": "OKP",
  "crv": "X25519",
  "x": "3pPHgcHYVYpOpB6ISwHdoPRB6jNgd8mM4nRyyj4H3aE",
  "d": "nWGxne0tAiV8Hk6kcy4rN0wMskjl9yND0N3Xeho9n6g",
  "kid": "recipient-key-1",
  "alg": "HPKE-3",
  "key_ops": "encrypt"
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

## Key Management

A single KEM key MUST NOT be used with multiple algorithms.  Each key and its
associated algorithm suite, comprising the KEM, KDF, and AEAD, should be managed independently.  This separation prevents unintended
interactions or vulnerabilities between suites, ensuring the integrity and security guarantees of each algorithm suite are
preserved.  Additionally, the same key MUST NOT be used for both key encryption and integrated encryption, as it may introduce security risks.
It creates algorithm confusion, increases the potential for key leakage, cross-suite attacks, and improper handling of the key.

A single recipient or sender key MUST NOT be used with both JOSE-HPKE and other algorithms as this might enable cross-protocol attacks.

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

## Ciphersuite Registration

This specification registers a number of ciphersuites for use with HPKE.
A ciphersuite is a group of algorithms, often sharing component algorithms such as hash functions, targeting a security level.
A JOSE-HPKE algorithm, is composed of the following choices:

- KEM Algorithm
- KDF Algorithm
- AEAD Algorithm

The "KEM", "KDF", and "AEAD" values are chosen from the HPKE IANA registry {{HPKE-IANA}}.

## JSON Web Signature and Encryption Algorithms

The following entries are added to the "JSON Web Signature and Encryption Algorithms" registry:

### HPKE-0

- Algorithm Name: HPKE-0
- Algorithm Description: Cipher suite for JOSE-HPKE using the DHKEM(P-256, HKDF-SHA256) KEM, the HKDF-SHA256 KDF and the AES-128-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{alg-mapping}} of this specification
- Algorithm Analysis Documents(s): {{RFC9180}}

### HPKE-1

- Algorithm Name: HPKE-1
- Algorithm Description: Cipher suite for JOSE-HPKE using the DHKEM(P-384, HKDF-SHA384) KEM, the HKDF-SHA384 KDF, and the AES-256-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{alg-mapping}} of this specification
- Algorithm Analysis Documents(s): {{RFC9180}}

### HPKE-2

- Algorithm Name: HPKE-2
- Algorithm Description: Cipher suite for JOSE-HPKE using the DHKEM(P-521, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the AES-256-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{alg-mapping}} of this specificationX
- Algorithm Analysis Documents(s): {{RFC9180}}

### HPKE-3

- Algorithm Name: HPKE-3
- Algorithm Description: Cipher suite for JOSE-HPKE using the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and the AES-128-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{alg-mapping}} of this specificationX
- Algorithm Analysis Documents(s): {{RFC9180}}

### HPKE-4

- Algorithm Name: HPKE-4
- Algorithm Description: Cipher suite for JOSE-HPKE using the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and the ChaCha20Poly1305 AEAD.
- Algorithm Usage Location(s): "alg, enc"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{alg-mapping}} of this specificationX
- Algorithm Analysis Documents(s): {{RFC9180}}

### HPKE-5

- Algorithm Name: HPKE-5
- Algorithm Description: Cipher suite for JOSE-HPKE using the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the AES-256-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{alg-mapping}} of this specificationX
- Algorithm Analysis Documents(s): {{RFC9180}}

### HPKE-6

- Algorithm Name: HPKE-6
- Algorithm Description: Cipher suite for JOSE-HPKE using the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the ChaCha20Poly1305 AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{alg-mapping}} of this specificationX
- Algorithm Analysis Documents(s): {{RFC9180}}

### int

- Algorithm Name: "int"
- Algorithm Description: Indicates that Integrated Encryption is being used
- Algorithm Usage Location(s): "enc"
- JOSE Implementation Requirements: Required
- Change Controller: IETF
- Specification Document(s): {{overview}} of this specification
- Algorithm Analysis Documents(s): {{RFC9180}}

## JSON Web Signature and Encryption Header Parameters

The following entries are added to the "JSON Web Key Parameters" registry:

### ek

- Header Parameter Name: "ek"
- Header Parameter Description: An encapsulated key as defined in { Section 5.1.1 of RFC9180 }
- Header Parameter Usage Location(s): JWE
- Change Controller: IETF
- Specification Document(s): {{encapsulated-keys}} of this specification

### psk_id

- Header Parameter Name: "psk_id"
- Header Parameter Description: A key identifier (kid) for the pre-shared key as defined in { Section 5.1.2 of RFC9180 }
- Header Parameter Usage Location(s): JWE
- Change Controller: IETF
- Specification Document(s): {{overview}} of this specification

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

-07

* Use "enc":"int" for integrated encryption.
* Described reasons for excluding authenticated HPKE.

-06

* Remove auth mode and auth_kid from the specification.

-05

* Removed incorrect text about HPKE algorithm names.
* Fixed #21: Comply with NIST SP 800-227 Recommendations for Key-Encapsulation Mechanisms.
* Fixed #19: Binding the Application Context.
* Fixed #18: Use of apu and apv in Recipeint context.
* Added new Section 7.1 (Authentication using an Asymmetric Key).
* Updated Section 7.2 (Key Management) to prevent cross-protocol attacks.
* Updated HPKE Setup info parameter to be empty.
* Added details on HPKE AEAD AAD, compression and decryption for HPKE Integrated Encryption.

-04

* Fixed #8: Use short algorithm identifiers, per the JOSE naming conventions.

-03

* Added new section 7.1 to discuss Key Management.
* HPKE Setup info parameter is updated to carry JOSE context-specific data for both modes.

-02

* Fixed #4: HPKE Integrated Encryption "enc: dir".
* Updated text on the use of HPKE Setup info parameter.
* Added Examples in Sections 5.1, 5.2 and 6.1.
* Use of registered HPKE  "alg" value in the recipient unprotected header for Key Encryption.

-01

* Apply feedback from call for adoption.
* Provide examples of auth and psk modes for JSON and Compact Serializations
* Simplify description of HPKE modes
* Adjust IANA registration requests
* Remove HPKE Mode from named algorithms
* Fix AEAD named algorithms

-00

* Created initial working group version from draft-rha-jose-hpke-encrypt-07
