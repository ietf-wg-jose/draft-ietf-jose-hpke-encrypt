---
title: "PQ/T Hybrid KEM: HPKE with JOSE/COSE"
abbrev: "PQ/T Hybrid KEM: HPKE with JOSE/COSE"
category: std

docname: draft-reddy-cose-jose-pqc-hybrid-hpke
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "COSE"
keyword:
 - PQC
 - COSE
 - JOSE
 - Hybrid
 - HPKE

venue:
  group: "cose"
  type: "Working Group"
  mail: "cose@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/cose/"
  

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
    organization:
    city:
    country: Germany
    email: "hannes.tschofenig@gmx.net"

 
normative:

informative:
 
  FIPS203:
     title: "Module-Lattice-based Key-Encapsulation Mechanism Standard"
     target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
     date: false
  HPKE-IANA:
     author:
        org: IANA
     title: Hybrid Public Key Encryption (HPKE) IANA Registry
     target: https://www.iana.org/assignments/hpke/hpke.xhtml
     date: false

     
--- abstract

This document outlines the construction of a PQ/T Hybrid Key Encapsulation Mechanism (KEM) in Hybrid Public-Key Encryption (HPKE) for integration with JOSE and COSE. It specifies the utilization of both traditional and Post-Quantum Cryptography (PQC) algorithms, referred to as PQ/T Hybrid KEM, within the context of JOSE and COSE.

--- middle

# Introduction

The migration to Post-Quantum Cryptography (PQC) is unique in the history of modern digital cryptography in that neither the traditional algorithms nor the post-quantum algorithms are fully trusted to protect data for the required data lifetimes. The traditional algorithms, such as RSA and elliptic curve, will fall to quantum cryptalanysis, while the post-quantum algorithms face uncertainty about the underlying mathematics, compliance issues, unknown vulnerabilities, hardware and software implementations that have not had sufficient maturing time to rule out classical cryptanalytic attacks and implementation bugs.

During the transition from traditional to post-quantum algorithms, there is a desire or a requirement for protocols that use both algorithm types. Hybrid key exchange refers to using multiple key exchange algorithms simultaneously and combining the result with the goal of providing security even if all but one of the component algorithms is broken. It is motivated by transition to post-quantum cryptography. 

HPKE offers a variant of public-key encryption of arbitrary-sized plaintexts for a recipient public key. The specifications for the use of HPKE with JOSE and COSE are described in {{?I-D.rha-jose-hpke-encrypt}} and {{?I-D.ietf-cose-hpke}}, respectively. HPKE can be extended to support PQ/T Hybrid KEM as defined in {{?I-D.connolly-cfrg-xwing-kem}}. This specification defines PQ/T Hybrid KEM in HPKE for use with JOSE and COSE. 

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document makes use of the terms defined in {{?I-D.ietf-pquip-pqt-hybrid-terminology}}. For the purposes of this document, it is helpful to be able to divide cryptographic algorithms into two classes:

"Traditional Algorithm":  An asymmetric cryptographic algorithm based on integer factorisation, finite field discrete logarithms, elliptic curve discrete logarithms, or related mathematical problems. In the context of JOSE, examples of traditional key exchange algorithms include Elliptic Curve Diffie-Hellman Ephemeral Static {{?RFC6090}} {{?RFC8037}}. In the context of COSE, examples of traditional key exchange algorithms include Ephemeral-Static (ES) DH and Static-Static (SS) DH {{?RFC9052}}. 

"Post-Quantum Algorithm":  An asymmetric cryptographic algorithm that is believed to be secure against attacks using quantum computers as well as classical computers. Examples of PQC key exchange algorithms include ML-KEM.

"Post-Quantum Traditional (PQ/T) Hybrid Scheme":  A multi-algorithm scheme where at least one component algorithm is a post-quantum algorithm and at least one is a traditional algorithm.

"PQ/T Hybrid Key Encapsulation Mechanism":  A multi-algorithm KEM made up of two or more component KEM algorithms where at least one is a post-quantum algorithm and at least one is a traditional algorithm.

# Construction

ML-KEM is a one-pass (store-and-forward) cryptographic mechanism for an originator to securely send keying material to a recipient using the recipient's ML-KEM public key. Three parameters sets for ML-KEMs are specified by {{FIPS203}}. In order of increasing security strength (and decreasing performance), these parameter sets
are ML-KEM-512, ML-KEM-768, and ML-KEM-1024. X-Wing {{?I-D.connolly-cfrg-xwing-kem}} uses a multi-algorithm scheme,
where one component algorithm is a post-quantum algorithm and another one is a traditional algorithm. X-Wing uses the final version of ML-KEM-768 and X25519. The Combiner function defined in Section 5.3 of {{?I-D.connolly-cfrg-xwing-kem}} combines the output of a post-quantum KEM and a traditional KEM to generate a single shared secret. 

# Ciphersuite Registration

This specification registers a number of PQ/T Hybrid KEMs for use with HPKE. A ciphersuite is thereby a combination of several algorithm configurations:

- KEM algorithm (PQ KEM + Traditional Algorithm,  for example, MLKEM768 + X25519 defined as "X-Wing" in {{?I-D.connolly-cfrg-xwing-kem}})
- KDF algorithm
- AEAD algorithm

The "KEM", "KDF", and "AEAD" values are conceptually taken from the HPKE IANA registry {{HPKE-IANA}}. Hence, JOSE and COSE cannot use an algorithm combination that is not already available with HPKE.


For readability the algorithm ciphersuites labels are built according to the following scheme:

~~~
   HPKE-<KEM>-<KDF>-<AEAD>
~~~

The HPKE PQ/T hybrid ciphersuites for JOSE and COSE are defined in {{IANA}}. Note that the PQ/T Hybrid KEM in HPKE is not an authenticated KEM. The HPKE Base mode can only be supported with the PQ/T Hybrid KEM.

# Security Considerations

The security considerations in [I-D.connolly-cfrg-xwing-kem] are to be taken into account.

The shared secrets computed in the hybrid key exchange should be computed in a way that achieves the "hybrid" property: the resulting secret is secure as long as at least one of the component key exchange algorithms is unbroken. PQC KEMs used in the manner described in this document MUST explicitly be designed to be secure in the event that the public key is reused, such as achieving IND-CCA2 security. ML-KEM has such security properties.

## Post-Quantum Security for Multiple Recipients 

In HPKE JWE Key Encryption, when encrypting the Content Encryption Key (CEK) for multiple recipients, it is crucial to consider the security requirements of the message to safeguard against "Harvest Now, Decrypt Later" attack. For messages requiring post-quantum security, all recipients MUST use algorithms supporting post-quantum cryptographic methods, such as PQC KEMs or Hybrid PQ/T KEMs. Using traditional algorithms (e.g., ECDH-ES) for any recipient in these scenarios compromises the overall security of the message.

# IANA Considerations {#IANA}

## JOSE

This document requests IANA to add new values to the "JSON Web Signature and Encryption Algorithms" registry.

### JOSE Algorithms Registry 

- Algorithm Name: HPKE-XWING-SHA256-AES256GCM
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the XWING Hybrid 
  KEM, the HKDF-SHA256 KDF, and the AES-256-GCM AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IANA
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

- Algorithm Name: HPKE-XWING-SHA256-ChaCha20Poly1305
- Algorithm Description: Cipher suite for JOSE-HPKE in Base Mode that uses the XWING Hybrid  
  KEM, the HKDF-SHA256 KDF, and the ChaCha20Poly1305 AEAD.
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IANA
- Specification Document(s): [[TBD: This RFC]]
- Algorithm Analysis Documents(s): TODO

### JSON Web Key Elliptic Curves Registrations

- Curve name: X-Wing
- Curve description: X-Wing key pairs
- JOSE Implementation Requirements: TBD
- Change Controller: IESG
- Reference: This Document

## COSE

This document requests IANA to add new values to the 'COSE Algorithms' registry.

### COSE Algorithms Registry 

*  Name: HPKE-Base-XWING-SHA256-AES256GCM
*  Value: TBD1 
*  Description: Cipher suite for COSE-HPKE in Base Mode that uses the XWING Hybrid KEM, the  
   HKDF-SHA256 KDF, and the AES-256-GCM AEAD.
*  Capabilities: [kty]
*  Change Controller: IANA
*  Reference: [[TBD: This RFC]]

*  Name: HPKE-Base-XWING-SHA256-ChaCha20Poly1305
*  Value: TBD2
*  Description: Cipher suite for COSE-HPKE in Base Mode that uses the XWING Hybrid      
   KEM, the HKDF-SHA256 KDF, and the ChaCha20Poly1305 AEAD.
*  Capabilities: [kty]
*  Change Controller: IANA
*  Reference: [[TBD: This RFC]]

### COSE Elliptic Curves Registrations

This document requests IANA to register the following value in the "COSE Elliptic Curves" registry.

*  Name: X-Wing
*  Value: TBD
*  Key type: OKP
*  Description: X-Wing
*  Change Controller: IESG
*  Reference: This document
*  Recommended: TBD

# Acknowledgments
{: numbered="false"}

Thanks to Ilari Liusvaara and Orie Steele for the discussion and comments.