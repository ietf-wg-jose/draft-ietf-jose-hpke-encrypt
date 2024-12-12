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
    country: Austria
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

# Overview

This specification describes two modes of use for HPKE in JWE:

  *  HPKE JWE Integrated Encryption, where HPKE is used to encrypt the plaintext.
  *  HPKE JWE Key Encryption, where HPKE is used to encrypt a content encryption key (CEK) and the CEK is subsequently used to encrypt the plaintext.

When "alg" and "enc" are both present in a protected header and when "iv" and "tag" are empty, the mode is HPKE JWE Integrated Encryption.

When "enc" is present in a protected header and "alg" is absent, the mode is HPKE JWE Key Encryption when a valid HPKE "alg" value is present in the unprotected headers.

HPKE supports several modes, which are described in Table 1 of {{RFC9180}}.

In JWE, the use of specific HPKE modes such as "mode_base" or "mode_auth_psk" is determined by the presence of the header parameters "psk_id" and "auth_kid".

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

The HPKE AEAD AAD MUST be set to the "JWE Additional Authenticated Data encryption parameter" defined in Step 14 of Section 5.1 of {{RFC7516}} which is repeated here for clarity:

Let the Additional Authenticated Data encryption parameter be ASCII(Encoded Protected Header).
However, if a JWE AAD value is present (which can only be the case when using the JWE JSON Serialization), instead let the Additional Authenticated Data encryption parameter be ASCII(Encoded Protected Header || '.' || BASE64URL(JWE AAD)).

## Encapsulated Keys

Encapsulated keys MUST be the base64url encoded encapsulated key as defined in Section 5.1.1 of {{RFC9180}}.

In HPKE JWE Integrated Encryption, JWE Encrypted Key is the encapsulated key.

In HPKE JWE Key Encryption, each recipient JWE Encrypted Key is the encrypted content encryption key, and the encapsulated key (ek) is found in the recipient header.

# Integrated Encryption

In HPKE JWE Integrated Encryption:

- The protected header MUST contain an "alg" that starts with "HPKE".
- The protected header MUST contain an "enc" and it MUST be set to the value "dir". It updates Section 4.1.2 of {{RFC7516}} to clarify that in case where HPKE JWE Integrated Encryption is used, setting "enc" set to "dir" is appropriate, as both the derivation of the CEK and the encryption of the plaintext are fully handled within the HPKE encryption.
- The protected header parameters "psk_id" and "auth_kid" MAY be present.
- The protected header parameter "ek" MUST NOT be present.
- The "encrypted_key" MUST be the base64url encoded encapsulated key as defined in Section 5.1.1 of {{RFC9180}}.
- The "iv", "tag" and "aad" members MUST NOT be present.
- The "ciphertext" MUST be the base64url encoded ciphertext as defined in Section 5.2 of {{RFC9180}}.
- The HPKE Setup info parameter MAY be used, and its values are not constrained by this specification. By default, it is empty unless apu or apv are present, in which case it will carry the JOSE context-specific data as defined in Section 4.6.2 of {{RFC7518}}, i.e., the concatenation of AlgorithmID, PartyUInfo, and PartyVInfo. It does not include Z, keydatalen, SuppPubInfo, or SuppPrivInfo. AlgorithmID is structured as defined in Section 4.6.2 of {{RFC7518}} and the Data field in AlgorithmID will be set to the octets of the ASCII representation of the "enc" Header Parameter value.

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

# Key Encryption

HPKE based recipients can be added alongside existing `ECDH-ES+A128KW` or `RSA-OAEP-384` recipients because HPKE is only used to encrypt the content encryption key, and because the protected header used in content encryption is passed to HPKE as Additional Authenticated Data.

In HPKE JWE Key Encryption:

- The protected header MUST NOT contain an "alg".
- The protected header MUST contain an "enc" that is registered in both the IANA HPKE AEAD Identifiers Registry, and the IANA JSON Web Signature and Encryption Algorithms Registry.
- The recipient unprotected header parameters "psk_id" and "auth_kid" MAY be present.
- The recipient unprotected header parameter "ek" MUST be present.
- The recipient unprotected header MUST contain a registered HPKE "alg" value.
- The "encrypted_key" MUST be the base64url encoded content encryption key as described in Step 15 in Section 5.1 of {{RFC7516}}.
- The recipient "encrypted_key" is as described in Section 7.2.1 of {{RFC7516}}.
- The "iv", "tag" JWE members MUST be present.
- The "aad" JWE member MAY be present.
- The "ciphertext" MUST be the base64url encoded ciphertext as described in Step 19 in Section 5.1 of {{RFC7516}}.
- The HPKE Setup info parameter MAY be used, and its values are not constrained by this specification. By default, it is empty unless apu or apv are present, in which case it will carry the JOSE context-specific data as defined in Section 4.6.2 of {{RFC7518}}, i.e., the concatenation of AlgorithmID, PartyUInfo, and PartyVInfo. It does not include Z, keydatalen, SuppPubInfo, or SuppPrivInfo. AlgorithmID is structured as defined in Section 4.6.2 of {{RFC7518}} and the Data field in AlgorithmID will be set to the octets of the ASCII representation of the "alg" (algorithm) Header Parameter value.

## Multiple Recipients

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

## Key Management

Reusing a single KEM key across multiple algorithm combinations MUST be avoided to maintain cryptographic security. Each key and its associated algorithm suite, comprising the KEM, KDF, and AEAD, should be managed independently. This separation prevents unintended interactions or vulnerabilities between suites, ensuring the integrity and security guarantees of each algorithm suite are preserved.
Additionally, the same key MUST NOT be used for both key wrapping and content encryption, as it may introduce security risks.  It
creates algorithm confusion, increases the potential for key leakage, cross-suite attacks, and improper handling of the key.

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
An HPKE ciphersuite, is composed of the following choices:

- HPKE Mode
- KEM Algorithm
- KDF Algorithm
- AEAD Algorithm

The "KEM", "KDF", and "AEAD" values are chosen from the HPKE IANA registry {{HPKE-IANA}}.

For readability the algorithm ciphersuites labels are built according to the following scheme:

~~~
HPKE-<KEM>-<KDF>-<AEAD>
~~~

The "HPKE Mode" is described in Table 1 of {{RFC9180}}:

- "Base" refers to "mode_base" described in Section 5.1.1 of {{RFC9180}},
which only enables encryption to the holder of a given KEM private key.
- "PSK" refers to "mode_psk", described in Section 5.1.2 of {{RFC9180}},
which authenticates using a pre-shared key.
- "Auth" refers to "mode_auth", described in Section 5.1.3 of {{RFC9180}},
which authenticates using an asymmetric key.
- "Auth_Psk" refers to "mode_auth_psk", described in Section 5.1.4 of {{RFC9180}},
which authenticates using both a PSK and an asymmetric key.

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

* Fixed #8: Use short algorithm identifiers, per the JOSE IANA registration instructions.

-01

* Apply feedback from call for adoption.
* Provide examples of auth and psk modes for JSON and Compact Serializations
* Simplify description of HPKE modes
* Adjust IANA registration requests
* Remove HPKE Mode from named algorithms
* Fix AEAD named algorithms

-00

* Created initial working group version from draft-rha-jose-hpke-encrypt-07
