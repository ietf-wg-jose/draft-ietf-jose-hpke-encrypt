---
title: "Use of Hybrid Public Key Encryption (HPKE) with JSON Object Signing and Encryption (JOSE)"
abbrev: "Use of HPKE in JOSE"
category: std

docname: draft-ietf-jose-hpke-encrypt
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

- Key Type (kty), see {{RFC7517}}.
- Content Encryption Key (CEK), is defined in {{RFC7517}}.
- Hybrid Public Key Encryption (HPKE) is defined in {{RFC9180}}.
- pkR is the public key of the recipient, as defined in {{RFC9180}}.
- skR is the private key of the recipient, as defined in {{RFC9180}}.
- Key Encapsulation Mechanism (KEM), see {{RFC9180}}.
- Key Derivation Function (KDF), see {{RFC9180}}.
- Authenticated Encryption with Associated Data (AEAD), see {{RFC9180}}.
- Additional Authenticated Data (AAD), see {{RFC9180}}.

# HPKE for JOSE

## Overview

JSON Web Encryption (JWE) {{RFC7516}} defines several serializations for expressing encrypted content with JSON: 

* Compact JWE Serialization 
* General JWE JSON Serialization
* Flattened JWE JSON Serialization

JSON Web Algorithms (JWA) {{Section 4.6 of RFC7518}} defines two ways to use public key cryptography with JWE:

- Direct Key Agreement
- Key Agreement with Key Wrapping

The specification enables Hybrid Public Key Encryption (HPKE) {{RFC9180}} to be used with the serializations defined in JWE.

Unless otherwise stated, no changes to the processes described in {{RFC7516}} have been made.

This specification describes two modes of use for HPKE in JWE:

  *  HPKE Direct Encryption mode, where HPKE is used to encrypt the plaintext. This mode can only be used with a single recipient. This setup is conceptually similar to Direct Key Agreement.
  
  *  HPKE Key Encryption mode, where HPKE is used to encrypt a content encryption key (CEK) and the CEK is subsequently used to encrypt the plaintext. This mode supports multiple recipients. This setup is conceptually similar to Key Agreement with Key Wrapping.

When the alg value or enc value is set to any of algorithms registered by this specification then the 'epk' header parameter MUST be present, and it MUST be a JSON Web Key as defined in {{EK}} of this document.

The "ek" member of an 'epk' will contain the base64url encoded "enc" value produced by the encapsulate operation of the HPKE KEM.

In all serializations, "ct" will be base64url encoded.

If the 'alg' header parameter is set to the "dir" value (as defined in {{IANA}}), HPKE is used in Direct Encryption mode; otherwise, it is in Key Encryption mode.

Interested readers will observe this is due to all recipients using the same JWE Protected Header when JSON Serializations are used, as described in {{Section 7.2.1 of RFC7516}}.

We provide the following table for additional clarity:

| Name                   | Recipients | Serializations | Content Encryption Key | Similar to
|---
| Direct Encryption      | 1          | Compact, JSON  | Derived from HPKE      | Direct Key Agreement
| Key Encryption         | 1 or More  | Compact, JSON  | Encrypted by HPKE      | Key Agreement with Key Wrapping
{: #serialization-mode-table align="left" title="JOSE HPKE Serializations and Modes"}

## HPKE Encryption

The message encryption process is as follows. 

1. The sending HPKE context is created by invoking invoking SetupBaseS() (Section 5.1.1 of {{RFC9180}}) with the recipient's public key "pkR" and "info". The HPKE specification defines the "info" parameter as a context information structure that is used to ensure that the derived keying material is bound to the context of the transaction. The SetupBaseS function will be called with the default value of an empty string for the 'info' parameter. This yields the context "sctxt" and an encapsulation key "enc". 

There exist two cases of HPKE plaintext which need to be distinguished:

*  In HPKE Direct Encryption mode, the plaintext "pt" passed into Seal
  is the content to be encrypted.  Hence, there is no intermediate
  layer utilizing a CEK.

*  In HPKE Key Encryption mode, the plaintext "pt" passed into
  Seal is the CEK. The CEK is a random byte sequence of length
  appropriate for the encryption algorithm. For example, AES-128-GCM 
  requires a 16 byte key and the CEK would therefore be 16 bytes long.

## HPKE Decryption

The recipient will create the receiving HPKE context by invoking SetupBaseR() (Section 5.1.1 of {{RFC9180}}) with "skR", "enc" (output of base64url decoded 'ek'), and "info" (empty string). This yields the context "rctxt". The receiver then decrypts "ct" by invoking the Open() method on "rctxt" (Section 5.2 of {{RFC9180}}) with "aad", yielding "pt" or an error on failure. 

The Open function will, if successful, decrypts "ct".  When decrypted, the result will be either the CEK (when Key Encryption mode is used), or the content (if Direct Encryption mode is used).  The CEK is the symmetric key used to decrypt the ciphertext.

## Encapsulated JSON Web Keys {#EK}

An encapsulated key is represented as JSON Web Key as described in { Section 4 of RFC7515 }.

The "kty" parameter MUST be "EK".

The "ek" parameter MUST be present, and MUST be the base64url encoded output of the encap operation defined for the HPKE KEM.

As described in { Section 4 of RFC7515 }, additional members can be present in the JWK; if not understood by implementations encountering them, they MUST be ignored.

This example demonstrates the representaton of an encapsulated key as a JWK.

~~~
{
   "kty": "EK",
   "ek": "BHpP-u5JKziyUpqxNQqb0apHx1ecH2UzcRlhHR4ngJVS__gNu21DqqgPweuPpjglnXDnOuQ4kt9tHCs3PUzPxQs"
}
~~~

### HPKE Direct Encryption

This mode only supports a single recipient.

HPKE is employed to directly encrypt the plaintext, and the resulting ciphertext is included in the JWE ciphertext. 

In HPKE Direct Encryption mode:

*  The "epk" Header Parameter MUST be present, it MUST contain an Encapsulated JSON Web Key and it MUST occur only within the JWE Protected Header.

*  The "alg" Header Parameter MUST be "dir", "enc" MUST be an HPKE algorithm from JSON Web Signature and Encryption Algorithms in {{JOSE-IANA}} and they MUST occur only within the JWE Protected Header.

*  The JWE Ciphertext MUST be the resulting HPKE ciphertext ('ct' value) encoded using base64url.

*  The JWE Initialization Vector value MUST be absent. 

*  The JWE Authentication Tag MUST be absent.

*  The JWE Encrypted Key MUST be absent.

*  The HPKE "aad" parameter MUST be set to the JWE Additional Authenticated Data encryption parameter defined in Step 14 of Section 5.1 of {{RFC7516}} as input. 


The following example demonstrates the use of Direct Encryption with Compact Serialization:

~~~
eyJhbGciOiJkaXIiLCJlbmMiOiJIUEtFLUJhc2UtUDI1Ni1TSEEyNTYtQUVTMTI4R0NNIiwiZXBrIjp7Imt0eSI6IkVLIiwiZWsiOiJCR05ranp0MDc2YnNSR2o3OGFYNUF6VF9IRU9KQmJZOXEyWm9fNWU3dGJLMGFQcXU0ZVQxV0kxNmp2UmxacXBNeXFaZlAtUndSNEp3dGF6XzhVOXRoWEEifX0...DG3qygxcMHw3iACy5mX_T4N4EqWc03W0nkTHjMJsC4nb6JS6vVj6wTGdlr5TOSr0ykaoyzpePXEvEyHhvpUwCyQQr6kbGlGuZsrJdUbZ728vmA.
~~~
{: #direct-encryption-compact align="left" title="Direct Encryption with Compact Serialization"}

In the above example, the JWE Protected Header value is: 

~~~
{
  "alg": "dir",
  "enc": "HPKE-Base-P256-SHA256-AES128GCM",
  "epk": {
    "kty": "EK",
    "ek": "BGNkjzt076bsRGj78aX5AzT_HEOJBbY9q2Zo_5e7tbK0aPqu4eT1WI16jvRlZqpMyqZfP-RwR4Jwtaz_8U9thXA"
  }
}
~~~

~~~
{
    "protected": "eyJhbGciOiJkaXIiLCJlbmMiOiJIUEtFLUJhc2UtUDI1Ni1TSEEyNTYtQUVTMTI4R0NNIiwiZXBrIjp7Imt0eSI6IkVLIiwiZWsiOiJCTzRFbGZXd0xKRDZWcERza3c5LWxWMm9OMDJ2U1FKTW55ZHk3enhvSVlKZ1kydk9taE44Q1BqSHdRM1NONkhTcnNHNElacVpHVUR3dExKZjBoeHFTWGsifX0",
    "ciphertext": "1ATsw0jshqPrv8CFcm9Rem9Wfi1Ygv30sozlRTtNNzcaaZ828GqP0AXtqQ1Msv8YXI9XZqh81MK3QnlZ7pOBC1BP7j00J1rrHujdb3zvnOpmJg"
}
~~~
{: #direct-encryption-json align="left" title="Direct Encryption with JSON Serialization"}

In the above example, the JWE Protected Header value is: 

~~~
{
  "alg": "dir",
  "enc": "HPKE-Base-P256-SHA256-AES128GCM",
  "epk": {
    "kty": "EK",
    "ek": "BGNkjzt076bsRGj78aX5AzT_HEOJBbY9q2Zo_5e7tbK0aPqu4eT1WI16jvRlZqpMyqZfP-RwR4Jwtaz_8U9thXA"
  }
}
~~~

### HPKE Key Encryption

This mode supports more than one recipient.

HPKE is used to encrypt the	Content Encryption Key (CEK), and the resulting ciphertext is included in the JWE Encrypted Key. The plaintext will be encrypted using the CEK as explained in Step 15 of Section 5.1 of {{RFC7516}}.

When there are multiple recipients, the sender MUST place the 'epk' parameter in the per-recipient unprotected header to indicate the use of HPKE. In this case, the 'enc' (Encryption Algorithm) Header Parameter MUST be a content encryption algorithm from JSON Web Signature and Encryption Algorithms in {{JOSE-IANA}}, and it MUST be present in the JWE Protected Header. The integrity-protected 'enc' parameter provides protection against an attacker who manipulates the encryption algorithm in the 'enc' parameter. This attack is discussed in {{?I-D.draft-ietf-lamps-cms-cek-hkdf-sha256}}.

In HPKE Key Encryption mode: 

*  The JWE Encrypted Key MUST be the resulting HPKE ciphertext ('ct' value) encoded using base64url.

The following example demonstrates the use of Key Encryption with General JSON Serialization:

~~~
{
  "protected": "eyJlbmMiOiJBMTI4R0NNIn0",
  "ciphertext": "S0qqrM3xXPUavbmL9LQkgUKRBu8BZ7DQWoT-mdNIZVU-ip_V-fbMokiGwp2aPM57DX3cXCK3TKHqdhZ8rSNduUja",
  "iv": "AzaXpooLg3ZxEASQ",
  "aad": "8J-SgCBhYWQ",
  "tag": "S0omWw35S0H7tyEHsmGLDw",
  "recipients": [
    {
      "encrypted_key": "yDVZLsO7-ecy_GCgEluwn9U723TCHNAzeYRRQPOfpHM",
      "header": {
        "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:adjwW6fyyZ94ZBjGjx_OpDEKHLGfd1ELkug_YmRAjCk",
        "alg": "HPKE-Base-P256-SHA256-AES128GCM",
        "epk": {
          "kty": "EK",
          "ek": "BHpP-u5JKziyUpqxNQqb0apHx1ecH2UzcRlhHR4ngJVS__gNu21DqqgPweuPpjglnXDnOuQ4kt9tHCs3PUzPxQs"
        }
      }
    },
    {
      "encrypted_key": "iS73TFqJ61gkmh4DHAXADx4wyftA7pnY",
      "header": {
        "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:D2FKlj9MTIQma5bwdOVXk5Zh3_d60knzlbmD-SyMNAI",
        "alg": "ECDH-ES+A128KW",
        "epk": {
          "kty": "EC",
          "crv": "P-256",
          "x": "nX6Y3DWC0olVe5H7-NkCzVDghsYSa_L9da3jzkHYkV8",
          "y": "wDshQdcaY0J08wx25V3ystQSNe_qjsCaaFeeRWJqcE0"
        }
      }
    }
  ]
}
~~~
{: #key-encryption-multiple-recipient-general-json align="left" title="Key Encryption (multiple recipient) General JSON Serialization"}

In the above example, the JWE Protected Header value is: 

~~~
{
   "enc": "A128GCM"
}
~~~

~~~
{
  "protected": "eyJhbGciOiAiSFBLRS1CYXNlLVAyNTYtU0hBMjU2LUFFUzEyOEdDTSIsImVuYyI6IkExMjhHQ00iLCJlcGsiOnsia3R5IjoiRUsiLCJlayI6IkJQUlRLbjhtUUw0aE4xYXlva1I4Z2twVHk1SFFsZDROMEhYWEI5Y1h0alVJUTM3enNKREw3VHVnVmttRDFhRllUeC0wYk0wdGZ4emVqTGN0U0RLak1RcyJ9fQ",
  "encrypted_key": "zR0ArfrVVRQ9-X_heDU2riwx36QxLBffRrKAWU-tLC4",
  "iv": "o3v11Hw6gUxUN-pY",
  "ciphertext": "Ny-2IDGHMI3MzVsUAVMGNoKAZfoewTZ1dkAIBikPy4eZUfHW_LPhhKpD6Mf4zYGkhAeLwGgJKjyDoFIj0EuDsEtJ",
  "tag": "0sfzHJvxVoWt02EPxMTh8w"
}
~~~
{: #key-encryption-single-recipient-flattened-json align="left" title="Key Encryption (single recipient) Flattened JSON Serialization"}

In the above example, the JWE Protected Header value is: 

~~~
{

  "alg": "HPKE-Base-P256-SHA256-AES128GCM",
  "enc": "A128GCM",  
  "epk": {
    "kty": "EK",
    "ek": "BPRTKn8mQL4hN1ayokR8gkpTy5HQld4N0HXXB9cXtjUIQ37zsJDL7TugVkmD1aFYTx-0bM0tfxzejLctSDKjMQs"
  }
}
~~~

~~~
eyJhbGciOiAiSFBLRS1CYXNlLVAyNTYtU0hBMjU2LUFFUzEyOEdDTSIsImVuYyI6IkExMjhHQ00iLCJlcGsiOnsia3R5IjoiRUsiLCJlayI6IkJKN3JkTmJrdnd1bnNzZGp1NVdEa0FhekxhQlgzSWRjTFJqeTFSRFNBOXNpajAwamR5YmFIdVFQVHQ2UDMxQmkwbkUya1lXXzdMX3RhQXFBRks3NURlayJ9fQ.xaAa0nFxNJxsQQ5J6EFdzUYROd2aV517o2kZnfwhO7s.AgBYEWTj-EMji17I.Ejwu2iEP4xs3FfGO_zTZYu35glQmUvd_qpHpvB1hNqg6Yz5ek3NsZRGMzd--HYWvABNslxBkRwrkZDXnv_BTgOTj.u0ac86ipoAwUZuYwkaKwNw
~~~
{: #key-encryption-single-recipient-compact align="left" title="Key Encryption (single recipient) Compact"}

In the above example, the JWE Protected Header value is: 

~~~
{
  "alg": "HPKE-Base-P256-SHA256-AES128GCM",
  "enc": "A128GCM",
  "epk": {
    "kty": "EK",
    "ek": "BJ7rdNbkvwunssdju5WDkAazLaBX3IdcLRjy1RDSA9sij00jdybaHuQPTt6P31Bi0nE2kYW_7L_taAqAFK75Dek"
  }
}
~~~


# Ciphersuite Registration

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
HPKE-<Mode>-<KEM>-<KDF>-<AEAD>
~~~

The "Mode" indicator may be populated with the following values from
Table 1 of {{RFC9180}}:

- "Base" refers to "mode_base" described in Section 5.1.1 of {{RFC9180}},
which only enables encryption to the holder of a given KEM private key.
- "PSK" refers to "mode_psk", described in Section 5.1.2 of {{RFC9180}},
which authenticates using a pre-shared key.
- "Auth" refers to "mode_auth", described in Section 5.1.3 of {{RFC9180}},
which authenticates using an asymmetric key.
- "Auth_Psk" refers to "mode_auth_psk", described in Section 5.1.4 of {{RFC9180}},
which authenticates using both a PSK and an asymmetric key.

For a list of ciphersuite registrations, please see {{IANA}}.

# Security Considerations

This specification is based on HPKE and the security considerations of
{{RFC9180}} are therefore applicable also to this specification.

HPKE assumes the sender is in possession of the public key of the recipient and
HPKE JOSE makes the same assumptions. Hence, some form of public key distribution
mechanism is assumed to exist but outside the scope of this document.

HPKE in Base mode does not offer authentication as part of the HPKE KEM. In this case 
JOSE constructs like JWS and JSON Web Tokens (JWTs) can be used to add authentication. 
HPKE also offers modes that offer authentication.

HPKE relies on a source of randomness to be available on the device. In Key Agreement 
with Key Wrapping mode, CEK has to be randomly generated and it MUST be
ensured that the guidelines in {{RFC8937}} for random number generations are followed. 

## Plaintext Compression

Implementers are advised to review Section 3.6 of {{RFC8725}}, which states: 
Compression of data SHOULD NOT be done before encryption, because such compressed data often reveals information about the plaintext.

## Header Parameters

Implementers are advised to review Section 3.10 of {{RFC8725}}, which comments on application processing of JWE Protected Headers.
Additionally, Unprotected Headers can contain similar information which an attacker could leverage to mount denial of service, forgery or injection attacks.

## Ensure Cryptographic Keys Have Sufficient Entropy

Implementers are advised to review Section 3.5 of {{RFC8725}}, which provides comments on entropy requirements for keys. This guidance is relevant to both public and private keys used in both Key Encryption and Direct Encryption. Additionally, this guidance is applicable to content encryption keys used in Key Encryption mode.

## Validate Cryptographic Inputs

Implementers are advised to review Section 3.4 of {{RFC8725}}, which provides comments on the validation of cryptographic inputs. This guidance is relevant to both public and private keys used in both Key Encryption and Direct Encryption, specifically focusing on the structure of the public and private keys, as well as the 'ek' value. These inputs are crucial for the HPKE KEM operations.

## Use Appropriate Algorithms

Implementers are advised to review Section 3.2 of {{RFC8725}}, which comments on the selection of appropriate algorithms.
This is guidance is relevant to both Key Encryption and Direct Encryption.
When using Key Encryption, the strength of the content encryption algorithm should not be significantly different from the strengh of the Key Encryption algorithms used.

#  IANA Considerations {#IANA}

This document adds entries to {{JOSE-IANA}}.

## JSON Web Key Types

The following entry is added to the "JSON Web Key Types" registry:

- "kty" Parameter Value: "EK"
- Key Type Description: HPKE Encapsulated Key Type (See issue #18)
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): [[TBD: This RFC]]

## JSON Web Key Parameters

The following entry is added to the "JSON Web Key Parameters" registry:

- Parameter Name: "ek"
- Parameter Description: Encapsulated Key
- Parameter Information Class: Public
- Used with "kty" Value(s): "EK"
- Specification Document(s): [[TBD: This RFC]]
   
## JSON Web Signature and Encryption Algorithms

The following entries are added to the "JSON Web Signature and Encryption Algorithms" registry:

- Algorithm Name: HPKE-Base-P256-SHA256-AES128GCM
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(P-256, HKDF-SHA256) KEM, the HKDF-SHA256 KDF and the AES-128-GCM AEAD.
- Algorithm Usage Location(s): "alg, enc"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-P384-SHA384-AES256GCM
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(P-384, HKDF-SHA384) KEM, the HKDF-SHA384 KDF, and the AES-256-GCM AEAD.
- Algorithm Usage Location(s): "alg, enc"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-P521-SHA512-AES256GCM
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(P-521, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the AES-256-GCM AEAD.
- Algorithm Usage Location(s): "alg, enc"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-X25519-SHA256-AES128GCM
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and the AES-128-GCM AEAD.
- Algorithm Usage Location(s): "alg, enc"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-X25519-SHA256-ChaCha20Poly1305
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and the ChaCha20Poly1305 AEAD.
- Algorithm Usage Location(s): "alg, enc"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-X448-SHA512-AES256GCM
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the AES-256-GCM AEAD.
- Algorithm Usage Location(s): "alg, enc"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-Base-X448-SHA512-ChaCha20Poly1305
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the ChaCha20Poly1305 AEAD.
- Algorithm Usage Location(s): "alg, enc"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

## JSON Web Signature and Encryption Header Parameters

The following entries are added to the "JSON Web Key Parameters" registry:

- Parameter Name: "psk_id"
- Parameter Description: A key identifier (kid) for the pre-shared key as defined in { Section 5.1.1 of RFC9180 }
- Parameter Information Class: Public
- Used with "kty" Value(s): *
- Change Controller: IETF
- Specification Document(s): [[This specification]]

- Parameter Name: "auth_kid"
- Parameter Description: A key identifier (kid) for the asymmetric key as defined in { Section 5.1.4 of RFC9180 }
- Parameter Information Class: Public
- Used with "kty" Value(s): *
- Change Controller: IETF
- Specification Document(s): [[This specification]]
 
--- back

# Acknowledgments
{: numbered="false"}

This specification leverages text from {{?I-D.ietf-cose-hpke}}. We would like to thank Matt Chanda, Ilari Liusvaara, Aaron Parecki and Filip Skokan for their feedback.


# Document History
{: numbered="false"}

-00

* Created initial working group version from draft-rha-jose-hpke-encrypt-07