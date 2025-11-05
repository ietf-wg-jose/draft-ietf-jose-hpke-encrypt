---
title: "Use of Hybrid Public Key Encryption (HPKE) with JSON Object Signing and Encryption (JOSE)"
abbrev: "Use of HPKE in JOSE"
category: std
updates: 7516

docname: draft-ietf-jose-hpke-encrypt-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "JOSE"
keyword:
 - Hybrid Public Key Encryption
 - HPKE
 - JSON Web Encryption
 - JWE
 - JSON Object Signing and Encryption
 - JOSE
 - Hybrid

venue:
  group: "jose"
  type: "Working Group"
  mail: "jose@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/jose/"
  github: "ietf-wg-jose/draft-ietf-jose-hpke-encrypt"
  latest: "https://ietf-wg-jose.github.io/draft-ietf-jose-hpke-encrypt/draft-ietf-jose-hpke-encrypt.html"

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
    city: London
    country: United Kingdom
    email: "aritra.banerjee@nokia.com"

 -
    ins: O. Steele
    name: Orie Steele
    organization: Tradeverifyd
    email: orie@or13.io
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
  I-D.ietf-hpke-hpke:
  RFC7516:
  RFC8725:
  RFC8259:
  IANA.JOSE:
     author:
        org: IANA
     title: JSON Web Signature and Encryption Algorithms
     target: https://www.iana.org/assignments/jose

informative:
  RFC4086:
  RFC7518:
  I-D.ietf-cose-hpke:

  IANA.HPKE:
     author:
        org: IANA
     title: Hybrid Public Key Encryption (HPKE)
     target: https://www.iana.org/assignments/hpke

  NIST.SP.800-56Ar3:
     author:
        org: National Institute of Standards and Technology
     title: Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography, NIST Special Publication 800-56A Revision 3
     target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf
     date: April 2018

---


--- abstract


This specification defines Hybrid Public Key Encryption (HPKE) for use with
JSON Object Signing and Encryption (JOSE). HPKE offers a variant of public key encryption
of arbitrary-sized plaintexts for a recipient public key, and provides security
against adaptive chosen ciphertext attacks (IND-CCA2-secure).

HPKE also includes a variant that authenticates possession of a pre-shared key.
HPKE works for any combination of an asymmetric KEM, key derivation
function (KDF), and authenticated encryption with additional data
(AEAD) encryption function.

This document defines the use of HPKE with JOSE.
The specification chooses a specific subset of the HPKE features to use with JOSE.


--- middle

# Introduction

Hybrid Public Key Encryption (HPKE) {{I-D.ietf-hpke-hpke}} is a public key encryption
(PKE) scheme that provides encryption of arbitrary-sized plaintexts given a
recipient's public key.
This specification enables JSON Web Encryption (JWE) {{RFC7516}} to leverage HPKE,
bringing support for HPKE encryption and KEMs to JWE,
and the possibility of utilizing future HPKE algorithms, including hybrid KEMs.

# Notational Conventions

{::boilerplate bcp14-tagged}

# Terminology

This specification uses the following abbreviations and terms:

- Content Encryption Key (CEK), is defined in {{RFC7516}}.
- Hybrid Public Key Encryption (HPKE) is defined in {{I-D.ietf-hpke-hpke}}.
- pkR is the public key of the recipient, as defined in {{I-D.ietf-hpke-hpke}}.
- skR is the private key of the recipient, as defined in {{I-D.ietf-hpke-hpke}}.
- Key Encapsulation Mechanism (KEM), see {{I-D.ietf-hpke-hpke}}.
- Key Derivation Function (KDF), see {{I-D.ietf-hpke-hpke}}.
- Authenticated Encryption with Associated Data (AEAD), see {{I-D.ietf-hpke-hpke}} and {{RFC7516}}.
- Additional Authenticated Data (AAD), see {{I-D.ietf-hpke-hpke}} and {{RFC7516}}.

This specification defines the following terms.  When the term is already defined in JWE {{RFC7516}}, the definition below replaces it.

Key Management Mode
: A method of determining the Content Encryption Key (CEK) value to use and whether the encryption uses a CEK. Key Management Modes employed by this specification are Key Encryption, Key Wrapping, Direct Key Agreement, Key Agreement with Key Wrapping, Direct Encryption, HPKE Integrated Encryption, and HPKE Key Encryption.

HPKE Integrated Encryption
: A Key Management Mode in which HPKE is used to directly encrypt the plaintext without the use of a Content Encryption Key (CEK)

HPKE Key Encryption
: A Key Management Mode in which HPKE is used to encrypt the Content Encryption Key (CEK)

# Overview {#overview}

This specification defines two new Key Management Modes for use with JWE:

  *  HPKE Integrated Encryption, in which HPKE is used to directly encrypt the plaintext without the use of a Content Encryption Key (CEK).
  *  HPKE Key Encryption, in which HPKE is used to encrypt the Content Encryption Key (CEK).

When "alg" is a JOSE-HPKE algorithm:

  * If "enc" is "int", HPKE Integrated Encryption is used.
  * If "enc" is an AEAD algorithm, the recipient Key Management mode is Key Encryption.

The HPKE key encapsulation mechanism (KEM), key derivation function (KDF), and authenticated encryption with additional data (AEAD) encryption function utilized depend on the JOSE-HPKE algorithm used. The HPKE AEAD encryption function is used internally by HPKE and is distinct from the JWE AEAD algorithm specified in "enc".

HPKE supports multiple modes, which are described in Table 1 of {{I-D.ietf-hpke-hpke}}.
In this specification, both "mode_base" and "mode_psk" are utilized.
When the "psk_id" JOSE Header parameter is present, the mode used is "mode_psk";
otherwise, the mode used is "mode_base".
(This specification does not use the "mode_auth" or "mode_auth_psk" HPKE modes.)

JWE supports both the JWE Compact Serialization, as described in {{Section 3.1 of RFC7516}}, and the JWE JSON Serialization, as described in {{Section 3.2 of RFC7516}}.
Certain JWE features are only supported in specific serializations.

For example, the Compact JWE Serialization does not support:

- additional authenticated data
- multiple recipients
- unprotected headers

HPKE Key Encryption can be used with "aad" but only when not expressed with Compact JWE Serialization.

Single recipient HPKE Key Encryption with no "aad" can be expressed in Compact JWE Serialization, so long as the recipient and sender use the same HPKE Setup process as described in {{Section 5 of I-D.ietf-hpke-hpke}}.

This specification updates the "enc" definition in {{Section 4.1.2 of RFC7516}}
by allowing the "enc" value "int" when the "alg" value is a JOSE-HPKE algorithm.
When "alg" is not a JOSE-HPKE algorithm and the "enc" value is "int",
the input MUST NOT be used and MUST be rejected.

## Auxiliary Authenticated Application Information

The HPKE "aad parameter" for Open() and Seal()
specified in {{Section 8.1 of I-D.ietf-hpke-hpke}}
is used with both HPKE Integrated Encryption and HPKE Key Encryption.
Its value is the Additional Authenticated Data encryption parameter value
computed in Step 14 of {{Section 5.1 of RFC7516}} (Message Encryption).

## Encapsulated Keys {#encapsulated-keys}

HPKE encapsulated key is defined in {{Section 5 of I-D.ietf-hpke-hpke}}.

In HPKE Integrated Encryption, the JWE Encrypted Key of the sole recipient is the HPKE encapsulated key.

In HPKE Key Encryption, each recipient's JWE Encrypted Key is the encrypted content encryption key, and the value of JOSE Header parameter "ek"
is the base64url encoding of the HPKE encapsulated key.

# Integrated Encryption

When using HPKE Integrated Encryption:

- The protected header MUST contain an "alg" that is JOSE-HPKE algorithm.
- The protected header MUST contain an "enc" with value "int". This is an explicit exception to requirement in {{Section 4.1.2 of RFC7516}} that
"enc" must be an AEAD algorithm. This is appropriate, as HPKE will perform plaintext encryption.
- The protected header parameter "psk_id" MAY be present.
- The protected header parameter "ek" MUST NOT be present.
- There MUST be exactly one recipient.
- The JWE Encrypted Key MUST be the encapsulated key, as defined in {{Section 5 of I-D.ietf-hpke-hpke}}.
- The JWE Initialization Vector and JWE Authentication Tag MUST be the empty octet sequence.
- The JWE AAD MAY be present when using the JWE JSON Serialization.
- The JWE Ciphertext is the ciphertext defined in {{Section 5.2 of I-D.ietf-hpke-hpke}}.
- The HPKE info parameter contains the encoding of the Recipient_structure, which is described in
  {{recipient_structure}}.
- The HPKE aad parameter MUST be set to the "Additional Authenticated Data encryption parameter", as specified in Step 14 of {{Section 5.1 of RFC7516}}.
- Then follow Steps 11-19 of {{Section 5.1 of RFC7516}} (Message Encryption).

When decrypting, the checks in {{Section 5.2 of RFC7516}},
Steps 1 through 5 MUST be performed. The JWE Encrypted Key in Step 2 is the
base64url-encoded encapsulated key.

## Compact Example

Below is an example of a Compact JWE using HPKE integrated encryption:

~~~
{::include-fold examples/compact_example.txt}
~~~

The keys used for this example are in {{keys-used}}.

# Key Encryption

When using the JWE JSON Serialization,
recipients using JOSE-HPKE can be added alongside other recipients
(e.g., those using `ECDH-ES+A128KW` or `RSA-OAEP-256`),
since HPKE is used to encrypt the Content Encryption Key,
which is then processed as specified in JWE.

The encoding of the protected header remains consistent with existing JWE rules.

When using HPKE Key Encryption:

- The Key Management Mode is Key Encryption.
- When all recipients use the same HPKE algorithm to secure the Content Encryption Key, the JWE Protected Header SHOULD contain "alg".
Otherwise, the JWE Protected Header (and JWE Shared Unprotected Header) MUST NOT contain "alg".
- JOSE Header parameter "alg" MUST be a JOSE-HPKE algorithm.
- JOSE Header parameter "psk_id" MAY be present.
- JOSE Header parameter "ek" MUST be present and contain the base64url-encoded HPKE encapsulated key.
- Recipient JWE Encrypted Key MUST be the ciphertext from HPKE Encryption.
- The HPKE info parameter contains the encoding of the Recipient_structure, which is described in {{recipient_structure}}.
- The HPKE AAD parameter defaults to the empty string; externally provided information MAY be used instead.
- THE HPKE plaintext MUST be set to the CEK.

The processing of "enc", "iv", "tag", "aad", and "ciphertext" is as already defined in {{RFC7516}}.
Implementations process these parameters as defined in {{RFC7516}};
no additional processing requirements are introduced by HPKE-based key encryption.

## JSON Example {#json-example}

Below is an example of a JWE using the JSON Serialization and HPKE key encryption:

~~~
{::include-fold examples/json_example.txt}
~~~

The keys used for this example are in {{keys-used}}.

# Recipient_structure {#recipient_structure}

The `Recipient_structure` is an input to the HPKE info parameter and provides context information used in key derivation. To ensure compactness and interoperability, this structure is encoded in a binary format. The encoding is as follows:

~~~
Recipient_structure = ASCII("JOSE-HPKE rcpt") ||
                      BYTE(255) ||
                      ASCII(content_encryption_alg) ||
                      BYTE(255) ||
                      recipient_extra_info
~~~

Where:

* ASCII("JOSE-HPKE rcpt"): A fixed ASCII string identifying the context of the structure.

* BYTE(255): A separator byte (0xFF) used to delimit fields.

* ASCII(content_encryption_alg): Identifies the algorithm with which the HPKE-encrypted key MUST be used. Its
  value MUST match the "enc" (encryption algorithm) header parameter in the JOSE Header. This field provides JWE context information to the key derivation process and serves two purposes:

  1. Ensures that derived key material is cryptographically domain-separated between the JWE HPKE integrated encryption and Key Encryption modes.
  2. Ensures that the derived key is bound to the selected content encryption algorithm.

* BYTE(255): A separator byte (0xFF) used to delimit fields.

* recipient_extra_info: An octet string containing additional context information that the application
  includes in the key derivation via the HPKE `info` parameter. Mutually known private information (a concept also utilized in {{NIST.SP.800-56Ar3}}) MAY be used in this input parameter. If no additional context information is provided, this field MUST be empty.

## Recipient_structure Example

The Recipient_structure encoded in binary as specified in {{recipient_structure}}, and using the field values
(next_layer_alg = "A128GCM", recipient_extra_info = ""), results in the following byte sequence:

~~~
"JOSE-HPKE rcpt\xffA128GCM\xff"
~~~

The corresponding hexadecimal representation is:

~~~
4a4f53452d48504b452072637074ffa131323847434dff
~~~

This value is directly used as the HPKE `info` parameter.

# Producing and Consuming JWEs

Sections 5.1 (Message Encryption) and 5.2 (Message Decryption) of {{RFC7516}}
are replaced by the following descriptions, which add processing rules for the
HPKE Integrated Encryption and HPKE Key Encryption Key Management Modes.

## Message Encryption

The message encryption process is as follows.
The order of the steps is not significant in cases where
there are no dependencies between the inputs and outputs of the steps.

1.  Determine the Key Management Mode employed by the algorithm
    used to determine the Content Encryption Key value.
    (This is the algorithm recorded in the
    `alg` (algorithm)
    Header Parameter of the resulting JWE.)

1.  When Key Wrapping, Key Encryption,
    or Key Agreement with Key Wrapping are employed,
    generate a random CEK value.
    See {{RFC4086}} for
    considerations on generating random values.
    The CEK MUST have a length equal to that
    required for the content encryption algorithm.

1.  When Direct Key Agreement or Key Agreement with Key Wrapping
    are employed, use the key agreement algorithm
    to compute the value of the agreed upon key.
    When Direct Key Agreement is employed,
    let the CEK be the agreed upon key.
    When Key Agreement with Key Wrapping is employed,
    the agreed upon key will be used to wrap the CEK.

1.  When Key Wrapping, Key Encryption,
    or Key Agreement with Key Wrapping are employed,
    encrypt the CEK to the recipient and let the result be the
    JWE Encrypted Key.

1.  When Direct Key Agreement or Direct Encryption are employed,
    let the JWE Encrypted Key be the empty octet sequence.

1.  When Direct Encryption is employed,
    let the CEK be the shared symmetric key.

1.  Compute the encoded key value BASE64URL(JWE Encrypted Key).

1.  If the JWE JSON Serialization is being used, repeat this process
    (steps 1-7)
    for each recipient.

1.  Generate a random JWE Initialization Vector of the correct size
    for the content encryption algorithm (if required for the algorithm);
    otherwise, let the JWE Initialization Vector be the empty octet sequence.

1.  Compute the encoded Initialization Vector value
    BASE64URL(JWE Initialization Vector).

1.  If a `zip` parameter was included,
    compress the plaintext using the specified compression algorithm
    and let M be the octet sequence representing the compressed plaintext;
    otherwise, let M be the octet sequence representing the plaintext.

1.  Create the JSON object(s) containing the desired set of Header Parameters,
    which together comprise the JOSE Header: one or more of the JWE Protected
    Header, the JWE Shared Unprotected
    Header, and the JWE Per-Recipient Unprotected Header.

1.  Compute the Encoded Protected Header value
    BASE64URL(UTF8(JWE Protected Header)).
    If the JWE Protected Header is not present
    (which can only happen when using the JWE JSON Serialization
    and no `protected` member is present),
    let this value be the empty string.

1.  Let the Additional Authenticated Data encryption parameter be
    ASCII(Encoded Protected Header).
    However, if a JWE AAD value is present
    (which can only be the case when using the JWE JSON Serialization),
    instead let the Additional Authenticated Data encryption parameter be
    ASCII(Encoded Protected Header || '.' || BASE64URL(JWE AAD)).

1.  Encrypt M using the CEK, the JWE Initialization Vector, and
    the Additional Authenticated Data value
    using the specified content encryption algorithm
    to create the JWE Ciphertext value and the JWE Authentication Tag
    (which is the Authentication Tag output from the encryption operation).

1.  Compute the encoded ciphertext value BASE64URL(JWE Ciphertext).

1.  Compute the encoded Authentication Tag value
    BASE64URL(JWE Authentication Tag).

1.  If a JWE AAD value is present,
    compute the encoded AAD value BASE64URL(JWE AAD).

1.  Create the desired serialized output.
    The Compact Serialization of this result is the string
    BASE64URL(UTF8(JWE Protected Header))
    || '.' || BASE64URL(JWE Encrypted Key)
    || '.' || BASE64URL(JWE Initialization Vector)
    || '.' || BASE64URL(JWE Ciphertext)
    || '.' || BASE64URL(JWE Authentication Tag).
    The JWE JSON Serialization is described in Section 7.2 of {{RFC7516}}.

## Message Decryption

The message decryption process is the reverse of the
encryption process.
The order of the steps is not significant in cases where
there are no dependencies between the inputs and outputs of the steps.
If any of these steps fail, the encrypted content cannot be validated.

When there are multiple recipients,
it is an application decision which of the recipients' encrypted content
must successfully validate for the JWE to be accepted.
In some cases, encrypted content for all recipients must successfully validate
or the JWE will be considered invalid.
In other cases, only the encrypted content for a single recipient
needs to be successfully validated.
However, in all cases, the encrypted content for at least one recipient
MUST successfully validate or the JWE MUST be considered invalid.

1.  Parse the JWE representation to extract the serialized values
    for the components of the JWE.
    When using the JWE Compact Serialization,
    these components are
    the base64url-encoded representations of
    the JWE Protected Header,
    the JWE Encrypted Key,
    the JWE Initialization Vector,
    the JWE Ciphertext, and
    the JWE Authentication Tag,
    and when using the JWE JSON Serialization,
    these components also include the base64url-encoded representation of
    the JWE AAD and the unencoded
    JWE Shared Unprotected Header and
    JWE Per-Recipient Unprotected Header values.
    When using the JWE Compact Serialization,
    the JWE Protected Header,
    the JWE Encrypted Key,
    the JWE Initialization Vector,
    the JWE Ciphertext, and
    the JWE Authentication Tag
    are represented as base64url-encoded values in that order,
    with each value being separated from the next by a single period ('.') character,
    resulting in exactly four delimiting period characters being used.
    The JWE JSON Serialization
    is described in Section 7.2 of {{RFC7516}}.

1.  Base64url decode the encoded representations of
    the JWE Protected Header,
    the JWE Encrypted Key,
    the JWE Initialization Vector,
    the JWE Ciphertext,
    the JWE Authentication Tag, and
    the JWE AAD,
    following the restriction that no line breaks, whitespace, or other additional characters have been used.

1.  Verify that the octet sequence resulting from decoding the encoded JWE Protected Header
    is a UTF-8-encoded representation of
    a completely valid JSON object
    conforming to {{RFC8259}};
    let the JWE Protected Header be this JSON object.

1.  If using the JWE Compact Serialization, let the JOSE Header be the
    JWE Protected Header.
    Otherwise, when using the JWE JSON Serialization,
    let the JOSE Header be the union of
    the members of the JWE Protected Header,
    the JWE Shared Unprotected Header and
    the corresponding JWE Per-Recipient Unprotected Header,
    all of which must be completely valid JSON objects.
    During this step,
    verify that the resulting JOSE Header does not contain duplicate
    Header Parameter names.
    When using the JWE JSON Serialization, this restriction includes
    that the same Header Parameter name also MUST NOT occur in
    distinct JSON object values that together comprise the JOSE Header.

1.  Verify that the implementation understands and can process
    all fields that it is required to support,
    whether required by this specification,
    by the algorithms being used,
    or by the `crit` Header Parameter value,
    and that the values of those parameters are also understood and supported.

1.  Determine the Key Management Mode employed by the algorithm
    specified by the
    `alg` (algorithm) Header Parameter.

1.  Verify that the JWE uses a key known to the recipient.

1.  When Direct Key Agreement or Key Agreement with Key Wrapping
    are employed, use the key agreement algorithm
    to compute the value of the agreed upon key.
    When Direct Key Agreement is employed,
    let the CEK be the agreed upon key.
    When Key Agreement with Key Wrapping is employed,
    the agreed upon key will be used to decrypt the JWE Encrypted Key.

1.  When Key Wrapping, Key Encryption,
    or Key Agreement with Key Wrapping are employed,
    decrypt the JWE Encrypted Key to produce the CEK.
    The CEK MUST have a length equal to that
    required for the content encryption algorithm.
    Note that when there are multiple recipients,
    each recipient will only be able to decrypt JWE Encrypted Key values
    that were encrypted to a key in that recipient's possession.
    It is therefore normal to only be able to decrypt one of the
    per-recipient JWE Encrypted Key values to obtain the CEK value.
    Also, see  Section 11.5 of {{RFC7516}} for security considerations
    on mitigating timing attacks.

1.  When Direct Key Agreement or Direct Encryption are employed,
    verify that the JWE Encrypted Key value is an empty octet sequence.

1.  When Direct Encryption is employed,
    let the CEK be the shared symmetric key.

1.  Record whether the CEK could be successfully determined for this recipient or not.

1.  If the JWE JSON Serialization is being used, repeat this process
    (steps 4-12)
    for each recipient contained in the representation.

1.  Compute the Encoded Protected Header value
    BASE64URL(UTF8(JWE Protected Header)).
    If the JWE Protected Header is not present
    (which can only happen when using the JWE JSON Serialization
    and no `protected` member is present),
    let this value be the empty string.

1.  Let the Additional Authenticated Data encryption parameter be
    ASCII(Encoded Protected Header).
    However, if a JWE AAD value is present
    (which can only be the case when using the JWE JSON Serialization),
    instead let the Additional Authenticated Data encryption parameter be
    ASCII(Encoded Protected Header || '.' || BASE64URL(JWE AAD)).

1.  Decrypt the JWE Ciphertext using the CEK, the JWE Initialization Vector,
    the Additional Authenticated Data value,
    and the JWE Authentication Tag
    (which is the Authentication Tag input to the calculation)
    using the specified content encryption algorithm,
    returning the decrypted plaintext and validating the JWE Authentication Tag
    in the manner specified for the algorithm,
    rejecting the input without emitting any decrypted output
    if the JWE Authentication Tag is incorrect.

1.  If a `zip` parameter was included,
    uncompress the decrypted plaintext using the specified compression algorithm.

1.  If there was no recipient for which all of the decryption steps succeeded,
    then the JWE MUST be considered invalid.
    Otherwise, output the plaintext.
    In the JWE JSON Serialization case, also return a result to the application
    indicating for which of the recipients the decryption succeeded and failed.

Finally, note that it is an application decision which algorithms
may be used in a given context.
Even if a JWE can be successfully decrypted,
unless the algorithms used in the JWE are acceptable
to the application, it SHOULD consider the JWE to be invalid.


# Mapping HPKE Keys to JWK for JOSE {#alg-mapping}

JWKs can be used to represent JOSE-HPKE private or public keys. For the algorithms defined in this document, the valid combinations of the
JWE Algorithm, "kty", and "crv" are shown in {{ciphersuite-kty-crv}}.

~~~
+---------------------+-----------------+
| JWE Algorithm       | JWK |           |
|                     | kty | crv       |
+---------------------+-----+-----------+
| HPKE-0, HPKE-7      | EC  | P-256     |
| HPKE-1              | EC  | P-384     |
| HPKE-2              | EC  | P-521     |
| HPKE-3, HPKE-4      | OKP | X25519    |
| HPKE-5, HPKE-6      | OKP | X448      |
+---------------------+-----+-----------+
~~~
{: #ciphersuite-kty-crv title="JWK Types and Curves for JOSE-HPKE Ciphersuites"}

## JWK Representation of a JOSE-HPKE Key with HPKE Ciphersuite

The example below is a JWK representation of a JOSE-HPKE public and private key:

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

It uses the "key_ops" value of "encrypt",
which is appropriate when using integrated encryption.

# Security Considerations

This specification is based on HPKE and the security considerations of
{{I-D.ietf-hpke-hpke}} are therefore applicable also to this specification.

HPKE assumes the sender is in possession of the public key of the recipient and
HPKE JOSE makes the same assumptions. Hence, some form of public key distribution
mechanism is assumed to exist but outside the scope of this document.

HPKE in Base mode does not offer authentication as part of the HPKE KEM.

HPKE relies on a source of randomness being available on the device.
In Key Agreement with Key Wrapping mode, the CEK has to be randomly generated.
The guidance on randomness in {{RFC4086}} applies.

## Key Management

A single KEM key MUST NOT be used with multiple KEM algorithms.
Each key and its associated algorithm suite, comprising the KEM, KDF, and AEAD,
should be managed independently.
This separation prevents unintended interactions or vulnerabilities between algorithms,
ensuring the integrity and security guarantees of each algorithm are preserved.
Additionally, the same key should not be used for both key encryption and integrated encryption, as it may introduce security risks.
It creates algorithm confusion, increases the potential for key leakage, cross-suite attacks, and improper handling of the key.

## Review JWT Best Current Practices

The guidance in {{RFC8725}} about encryption is also pertinent to this specification.

# Ciphersuite Registration

This specification registers a number of ciphersuites for use with HPKE.
A ciphersuite is a group of algorithms, often sharing component algorithms such as hash functions, targeting a security level.
A JOSE-HPKE algorithm makes choices for the following HPKE parameters:

- KEM Algorithm
- KDF Algorithm
- AEAD Algorithm

The "KEM", "KDF", and "AEAD" values are chosen from the IANA HPKE registry {{IANA.HPKE}}.

All JOSE-HPKE algorithm identifiers registered by this specification begin with the string "HPKE-".
Future JOSE-HPKE ciphersuite names registered MUST also follow this convention.

#  IANA Considerations {#IANA}

## JSON Web Signature and Encryption Algorithms

The following entries are added to the IANA "JSON Web Signature and Encryption Algorithms" registry {{IANA.JOSE}} established by {{RFC7518}}:

### HPKE-0

- Algorithm Name: HPKE-0
- Algorithm Description: Cipher suite for JOSE-HPKE using the DHKEM(P-256, HKDF-SHA256) KEM, the HKDF-SHA256 KDF and the AES-128-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{alg-mapping}} of this specification
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-hpke}}

### HPKE-1

- Algorithm Name: HPKE-1
- Algorithm Description: Cipher suite for JOSE-HPKE using the DHKEM(P-384, HKDF-SHA384) KEM, the HKDF-SHA384 KDF, and the AES-256-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{alg-mapping}} of this specification
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-hpke}}

### HPKE-2

- Algorithm Name: HPKE-2
- Algorithm Description: Cipher suite for JOSE-HPKE using the DHKEM(P-521, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the AES-256-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{alg-mapping}} of this specification
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-hpke}}

### HPKE-3

- Algorithm Name: HPKE-3
- Algorithm Description: Cipher suite for JOSE-HPKE using the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and the AES-128-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{alg-mapping}} of this specification
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-hpke}}

### HPKE-4

- Algorithm Name: HPKE-4
- Algorithm Description: Cipher suite for JOSE-HPKE using the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and the ChaCha20Poly1305 AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{alg-mapping}} of this specification
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-hpke}}

### HPKE-5

- Algorithm Name: HPKE-5
- Algorithm Description: Cipher suite for JOSE-HPKE using the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the AES-256-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{alg-mapping}} of this specification
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-hpke}}

### HPKE-6

- Algorithm Name: HPKE-6
- Algorithm Description: Cipher suite for JOSE-HPKE using the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the ChaCha20Poly1305 AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{alg-mapping}} of this specification
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-hpke}}

### HPKE-7

- Algorithm Name: HPKE-7
- Algorithm Description: Cipher suite for JOSE-HPKE using the DHKEM(P-256, HKDF-SHA256) KEM, the HKDF-SHA256 KDF and the A256GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{alg-mapping}} of this specification
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-hpke}}

### int

- Algorithm Name: int
- Algorithm Description: Indicates that HPKE Integrated Encryption is being used
- Algorithm Usage Location(s): "enc"
- JOSE Implementation Requirements: Required
- Change Controller: IETF
- Specification Document(s): {{overview}} of this specification
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-hpke}}

## JSON Web Signature and Encryption Header Parameters

The following entries are added to the IANA "JSON Web Key Parameters" registry {{IANA.JOSE}}:

### ek

- Header Parameter Name: "ek"
- Header Parameter Description: A base64url-encoded encapsulated key, as defined in {{Section 5 of I-D.ietf-hpke-hpke}}
- Header Parameter Usage Location(s): JWE
- Change Controller: IETF
- Specification Document(s): {{encapsulated-keys}} of this specification

### psk_id

- Header Parameter Name: "psk_id"
- Header Parameter Description: A base64url-encoded key identifier (kid) for the pre-shared key, as defined in {{Section 5.1.2 of I-D.ietf-hpke-hpke}}
- Header Parameter Usage Location(s): JWE
- Change Controller: IETF
- Specification Document(s): {{overview}} of this specification

--- back

# Keys Used in Examples {#keys-used}

This private key and its implied public key are used the examples:

~~~ text
{
  "kty": "EC",
  "use": "enc",
  "alg": "HPKE-0",
  "kid": "G5N__CqMv_kJGieGSFuAugvl0jrQJCZ3yKwVK6sUM4o",
  "crv": "P-256",
  "x": "gixQJ0qg4Ag-6HSMaIEDL_zbDhoXavMyKlmdn__AQVE",
  "y": "ZxTgRLWaKONCL_GbZKLNPsW9EW6nBsN4AwQGEFAFFbM",
  "d": "g2DXtKapi2oN2zL_RCWX8D4bWURHCKN2-ZNGC05ZaR8"
}
~~~

# Acknowledgments
{: numbered="false"}

This specification leverages text from {{?I-D.ietf-cose-hpke}}.
We would like to thank
Richard Barnes,
Brian Campbell,
Matt Chanda,
Ilari Liusvaara,
Neil Madden,
Aaron Parecki,
Filip Skokan,
and
Sebastian Stenzel
for their contributions to the specification.

# Document History
{: numbered="false"}

-15

* Defined the new HPKE Integrated Encryption and HPKE Key Encryption Key Management Mode for JWE {{RFC7516}}.
* Updated the encryption and decryption descriptions in JWE accordingly.
* Many editorial improvements.

-14

* Add HPKE-7
* Update to Recipient_structure
* Removed text related to apu and apv.
* Updated description of mutually known private information.

-13

* Removed orphan text about AKP kty field
* Fixed bug in "include-fold" syntax
* Switched reference from RFC 9180 to
  draft-ietf-hpke-hpke
* Editorial improvements to abstract and
  introduction.
* Removed Section 8.2 "Static Asymmetric
  Authentication in HPKE"

-12

* Added the recipient_structure

-11

* Fix too long lines

-10

* Addressed WGLC review comments by Neil Madden and Sebastian Stenzel.

-09

* Corrected examples.

-08

* Use "enc":"int" for integrated encryption.
* Described reasons for excluding authenticated HPKE.
* Stated that mutually known private information MAY be used as the HPKE info value.

-07

* Clarifications

-06

* Remove auth mode and auth_kid from the specification.
* HPKE AAD for JOSE HPKE Key Encryption is now empty.

-05

* Removed incorrect text about HPKE algorithm names.
* Fixed #21: Comply with NIST SP 800-227 Recommendations for Key-Encapsulation Mechanisms.
* Fixed #19: Binding the Application Context.
* Fixed #18: Use of apu and apv in Recipient context.
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
