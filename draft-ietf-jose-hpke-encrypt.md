---
title: "Use of Hybrid Public Key Encryption (HPKE) with JSON Web Encryption (JWE)"
abbrev: "Use of HPKE in JWE"
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
  RFC7517:
  RFC8725:
  RFC8259:
  RFC8937:

informative:
  RFC8792:
  RFC7515:
  RFC7518:
  RFC9864:
  I-D.ietf-cose-hpke:

  IANA.HPKE:
     author:
        org: IANA
     title: Hybrid Public Key Encryption (HPKE)
     target: https://www.iana.org/assignments/hpke

  IANA.JOSE:
     author:
        org: IANA
     title: JSON Web Signature and Encryption Algorithms
     target: https://www.iana.org/assignments/jose

  NIST.SP.800-56Ar3:
     author:
        org: National Institute of Standards and Technology
     title: Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography, NIST Special Publication 800-56A Revision 3
     target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf
     date: April 2018

---


--- abstract

This specification defines how to use Hybrid Public Key Encryption (HPKE) with
JSON Web Encryption (JWE).
HPKE enables public key encryption
of arbitrary-sized plaintexts to a recipient's public key, and provides security
against adaptive chosen ciphertext attacks.
This specification chooses a specific subset of the HPKE features to use with JWE.

This specification updates RFC 7516 (JWE) to enable use of
Integrated Encryption as a Key Management Mode.

--- middle

# Introduction

Hybrid Public Key Encryption (HPKE) {{I-D.ietf-hpke-hpke}} is a public key encryption
(PKE) scheme that provides encryption of arbitrary-sized plaintexts to a
recipient's public key.
This specification enables JSON Web Encryption (JWE) {{RFC7516}} to leverage HPKE,
bringing support for HPKE encryption and KEMs to JWE,
and the possibility of utilizing future HPKE algorithms.

# Notational Conventions

{::boilerplate bcp14-tagged}

# Terminology {#terminology}

This specification uses the following abbreviations and terms:

- Content Encryption Key (CEK), Header Parameter, and JOSE Header,
  as defined in {{RFC7516}}.
- Hybrid Public Key Encryption (HPKE), as defined in {{I-D.ietf-hpke-hpke}}.
- pkR is the public key of the recipient, as defined in {{I-D.ietf-hpke-hpke}}.
- skR is the private key of the recipient, as defined in {{I-D.ietf-hpke-hpke}}.
- Key Encapsulation Mechanism (KEM), per {{I-D.ietf-hpke-hpke}}.
- Key Derivation Function (KDF), per {{I-D.ietf-hpke-hpke}}.
- Authenticated Encryption with Associated Data (AEAD); see {{I-D.ietf-hpke-hpke}} and {{RFC7516}}.
- Additional Authenticated Data (AAD); see {{I-D.ietf-hpke-hpke}} and {{RFC7516}}.

This specification defines the following terms:

Key Management Mode
: A method of determining whether a Content Encryption Key (CEK) value is used
  and, if so, what CEK value to use.
  Each algorithm used for making these determinations uses a
  specific Key Management Mode.
  Key Management Modes employed by this specification are
  Key Encryption,
  Key Wrapping,
  Direct Key Agreement,
  Key Agreement with Key Wrapping,
  Direct Encryption,
  and
  Integrated Encryption.
  Of these, only Integrated Encryption is defined by this
  specification; the remaining modes are defined in {{RFC7516}}
  and are included here because this specification replaces the
  Message Encryption and Message Decryption procedures
  of {{RFC7516}} in their entirety.

Integrated Encryption
: A Key Management Mode in which the plaintext is directly encrypted
  without the use of a Content Encryption Key (CEK).
  This mode corresponds to the Single-Shot API defined in
  {{Section 6.1 of I-D.ietf-hpke-hpke}}, which is used in
  cases where applications encrypt only a single message to
  a recipient's public key. This mode is appropriate when there is
  exactly one recipient and no separate content encryption algorithm
  is required.

The definition of Key Management Mode above replaces the one in JWE {{RFC7516}}.

# Overview {#overview}

This specification defines the use of HPKE in JWE for two Key Management Modes:

* Key Encryption, and
* Integrated Encryption.

It specifies the Integrated Encryption Key Management Mode and registers the
corresponding JWE algorithm identifiers for both modes. Distinct JWE algorithms
are defined for Key Encryption and Integrated Encryption
so that they are fully specified, as required by {{RFC9864}}.

Test vectors for all algorithms defined in this document are provided in
{{test-vectors}}.

When the Key Management Mode is Integrated Encryption, HPKE is used to directly
encrypt the plaintext, and the "enc" header parameter MUST NOT be included.
This specification updates the definition of the "enc" header parameter in
{{Section 4.1.2 of RFC7516}} to require that it be omitted when Integrated
Encryption is used.

When the Key Management Mode is Key Encryption,
HPKE is used to encrypt the Content Encryption Key (CEK).
In this mode, the "enc" header parameter is used as specified in JWE {{RFC7516}}.
The HPKE AEAD encryption function used internally by HPKE
is distinct from the JWE AEAD algorithm specified in "enc".

In both Key Management Modes,
the HPKE key encapsulation mechanism (KEM), key derivation function (KDF),
and authenticated encryption with additional data (AEAD) encryption function
utilized depend on the JWE algorithm used.

HPKE supports two modes, which are described in Table 1 of {{I-D.ietf-hpke-hpke}}.
In this specification, both "mode_base" and "mode_psk" are supported
for both Key Management Modes.
When the "psk_id" header parameter is present, the HPKE mode is "mode_psk";
otherwise, the HPKE mode is "mode_base".

JWE supports two kinds of serializations:

* the JWE Compact Serialization described in {{Section 3.1 of RFC7516}}, and
* the JWE JSON Serialization described in {{Section 3.2 of RFC7516}}.

Certain JWE features are only supported in specific serializations.
For example, the JWE Compact Serialization does not support:

- the additional authenticated data header parameter "aad",
- multiple recipients, and
- unprotected header parameters.

Key Encryption can be used with the "aad" header parameter
when using the JWE JSON Serialization.
Single recipient Key Encryption with no "aad" header parameter can be expressed
in the JWE Compact Serialization.

## Encapsulated Secrets {#encapsulated-secrets}

HPKE encapsulated secret is defined in {{Section 5 of I-D.ietf-hpke-hpke}}.

When using Integrated Encryption, the JWE Encrypted Key of the sole recipient
is the HPKE encapsulated secret.

When using Key Encryption, each recipient's JWE Encrypted Key
is the encrypted content encryption key, and the value of header parameter "ek"
is the base64url encoding of the HPKE encapsulated secret.

# Integrated Encryption

When using Integrated Encryption with HPKE:

- The protected header MUST contain an "alg" value that is
  an HPKE JWE algorithm using Integrated Encryption.
- The "enc" header parameter MUST NOT be present.
  This is because no separate content encryption algorithm is used in this mode.
- The protected header parameter "psk_id" MAY be present.
- The header parameter "ek" MUST NOT be present.
- There MUST be exactly one recipient.
- The JWE Encrypted Key MUST be the encapsulated secret, as defined in {{Section 5 of I-D.ietf-hpke-hpke}}.
- The JWE Initialization Vector and JWE Authentication Tag MUST be the empty octet sequence.
- The JWE AAD MAY be present when using the JWE JSON Serialization.
- The HPKE aad parameter MUST be set to the "Additional Authenticated Data encryption parameter" value specified in Step 15 of {{encryption}}.
- The HPKE info parameter defaults to the empty octet sequence;
  mutually known private information (a concept also utilized in {{NIST.SP.800-56Ar3}})
  MAY be used instead so the application can include it during key derivation.
- The JWE Ciphertext is the ciphertext from the HPKE encryption,
  as defined in {{Section 5.2 of I-D.ietf-hpke-hpke}}.

## Integrated Encryption Algorithms using HPKE {#int-algs}

The following JWE algorithms using HPKE are defined for use with
Integrated Encryption as the Key Management Mode:

| "alg"  | HPKE KEM                   | HPKE KDF    | HPKE AEAD        |
| ------ | -------------------------- | ----------- | ---------------- |
| HPKE-0 | DHKEM(P-256, HKDF-SHA256)  | HKDF-SHA256 | AES-128-GCM      |
| HPKE-1 | DHKEM(P-384, HKDF-SHA384)  | HKDF-SHA384 | AES-256-GCM      |
| HPKE-2 | DHKEM(P-521, HKDF-SHA512)  | HKDF-SHA512 | AES-256-GCM      |
| HPKE-3 | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | AES-128-GCM      |
| HPKE-4 | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | ChaCha20Poly1305 |
| HPKE-5 | DHKEM(X448, HKDF-SHA512)   | HKDF-SHA512 | AES-256-GCM      |
| HPKE-6 | DHKEM(X448, HKDF-SHA512)   | HKDF-SHA512 | ChaCha20Poly1305 |
| HPKE-7 | DHKEM(P-256, HKDF-SHA256)  | HKDF-SHA256 | AES-256-GCM      |
{: #ciphersuite-int-algs title="Algorithms using HPKE for Integrated Encryption"}

The HPKE KEM, KDF, and AEAD values are chosen from the IANA HPKE registry {{IANA.HPKE}}.

# Key Encryption

When using the JWE JSON Serialization,
recipients using Key Encryption with HPKE can be added alongside other recipients
(e.g., those using "ECDH-ES+A128KW" or "RSA-OAEP-256"),
since HPKE is used to encrypt the Content Encryption Key (CEK).

When using Key Encryption with HPKE:

- The "alg" header parameter MUST be an HPKE JWE algorithm using Key Encryption.
- The header parameter "psk_id" MAY be present.
- The header parameter "ek" MUST be present and contain the base64url-encoded HPKE encapsulated secret.
- The HPKE aad parameter defaults to the empty octet sequence.
- The HPKE info parameter is set to the value of the "Recipient_structure" defined below.
- The HPKE plaintext MUST be set to the CEK.
- The recipient's JWE Encrypted Key is the ciphertext from the HPKE Encryption,
  as defined in {{Section 5.2 of I-D.ietf-hpke-hpke}}.

## Recipient_structure {#recipient_structure}

The "Recipient_structure" used as the value of the HPKE info parameter
when performing Key Encryption with HPKE
provides context information used in key derivation.
To ensure compactness and interoperability,
this structure is encoded in a binary format.
The encoding is as follows:

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

* ASCII(content_encryption_alg): Identifies the content encryption algorithm
  with which the HPKE-encrypted Content Encryption Key (CEK) is used.
  Its value MUST be the "enc" (encryption algorithm) header parameter value
  in the JOSE Header.
  This field provides JWE context information to the HPKE key schedule,
  which ensures that the encapsulated secret is bound to the selected content encryption algorithm.

* BYTE(255): A separator byte (0xFF) used to delimit fields.

* recipient_extra_info: An octet string containing additional context information
  that the application includes in the key derivation.
  Mutually known private information (a concept also utilized in {{NIST.SP.800-56Ar3}}) MAY be used in this input parameter.
  If no additional context information is provided, this field MUST be the empty octet sequence.

Note that Integrated Encryption does not use the "Recipient_structure" because the JWE Protected Header and JWE AAD are included in the HPKE aad value, which binds these parameters to the ciphertext.

### Recipient_structure Example

The "Recipient_structure" encoded in binary as specified in {{recipient_structure}}, and using the field values
(content_encryption_alg = "A128GCM", recipient_extra_info = ""),
results in the following byte sequence:

~~~
"JOSE-HPKE rcpt\xffA128GCM\xff"
~~~

The corresponding hexadecimal representation is:

~~~
4a4f53452d48504b452072637074ff4131323847434dff
~~~

This value is used as the HPKE "info" parameter when performing Key Encryption with HPKE.


## Key Encryption Algorithms using HPKE {#ke-algs}

The following JWE algorithms using HPKE are defined for use with
Key Encryption as the Key Management Mode:

| "alg"     | HPKE KEM                   | HPKE KDF    | HPKE AEAD        |
| --------- | -------------------------- | ----------- | ---------------- |
| HPKE-0-KE | DHKEM(P-256, HKDF-SHA256)  | HKDF-SHA256 | AES-128-GCM      |
| HPKE-1-KE | DHKEM(P-384, HKDF-SHA384)  | HKDF-SHA384 | AES-256-GCM      |
| HPKE-2-KE | DHKEM(P-521, HKDF-SHA512)  | HKDF-SHA512 | AES-256-GCM      |
| HPKE-3-KE | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | AES-128-GCM      |
| HPKE-4-KE | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | ChaCha20Poly1305 |
| HPKE-5-KE | DHKEM(X448, HKDF-SHA512)   | HKDF-SHA512 | AES-256-GCM      |
| HPKE-6-KE | DHKEM(X448, HKDF-SHA512)   | HKDF-SHA512 | ChaCha20Poly1305 |
| HPKE-7-KE | DHKEM(P-256, HKDF-SHA256)  | HKDF-SHA256 | AES-256-GCM      |
{: #ciphersuite-ke-algs title="Algorithms using HPKE for Key Encryption"}

The HPKE KEM, KDF, and AEAD values are chosen from the IANA HPKE registry {{IANA.HPKE}}.


# Producing and Consuming JWEs

Sections 5.1 (Message Encryption) and 5.2 (Message Decryption) of {{RFC7516}}
are replaced by the following sections,
which add processing rules for using Integrated Encryption as the Key Management Mode.

## Message Encryption {#encryption}

The message encryption process is as follows.
The order of the steps is not significant in cases where
there are no dependencies between the inputs and outputs of the steps.

1.  Determine the Key Management Mode employed by the algorithm
    used to determine the Content Encryption Key value.
    (This is the algorithm recorded in the
    "alg" (algorithm)
    Header Parameter of the resulting JWE.)

1.  When Key Wrapping, Key Encryption,
    or Key Agreement with Key Wrapping is employed,
    generate a random CEK value to use for subsequent steps
    unless one was already generated for a previously
    processed recipient, in which case, let that be the one used
    for subsequent steps.
    See {{RFC8937}} for
    considerations on generating random values.
    The CEK MUST have a length equal to that
    required for the content encryption algorithm.

1.  When Direct Key Agreement or Key Agreement with Key Wrapping
    is employed, use the key agreement algorithm
    to compute the value of the agreed upon key.
    When Direct Key Agreement is employed,
    let the CEK be the agreed upon key.
    When Key Agreement with Key Wrapping is employed,
    the agreed upon key will be used to wrap the CEK.

1.  When Key Wrapping, Key Encryption,
    or Key Agreement with Key Wrapping is employed,
    encrypt the CEK to the recipient and let the result be the
    JWE Encrypted Key.

1.  When Direct Key Agreement or Direct Encryption is employed,
    let the JWE Encrypted Key be the empty octet sequence.

1.  When Direct Encryption is employed,
    let the CEK be the shared symmetric key.

1.  When Integrated Encryption is employed,
    let the JWE Encrypted Key be as specified by the Integrated Encryption algorithm.

1.  Compute the encoded key value BASE64URL(JWE Encrypted Key).

1.  If the JWE JSON Serialization is being used, and
    there are multiple recipients, repeat this process
    (steps 1-8)
    for each recipient.

1.  Generate a random JWE Initialization Vector of the correct size
    for the content encryption algorithm (if required for the algorithm);
    otherwise, let the JWE Initialization Vector be the empty octet sequence.

1.  Compute the encoded Initialization Vector value
    BASE64URL(JWE Initialization Vector).

1.  If a "zip" parameter was included,
    compress the plaintext using the specified compression algorithm,
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
    and no "protected" member is present),
    let this value be the empty string.

1.  Let the Additional Authenticated Data encryption parameter be
    ASCII(Encoded Protected Header).
    However, if a JWE AAD value is present
    (which can only be the case when using the JWE JSON Serialization),
    instead let the Additional Authenticated Data encryption parameter be
    ASCII(Encoded Protected Header || '.' || BASE64URL(JWE AAD)).

1.  If Integrated Encryption is not being employed,
    encrypt M using the CEK, the JWE Initialization Vector, and
    the Additional Authenticated Data value
    using the specified content encryption algorithm
    to create the JWE Ciphertext value and the JWE Authentication Tag
    (which is the Authentication Tag output from the encryption operation).

1.  If Integrated Encryption is being employed,
    encrypt M
    using the specified Integrated Encryption algorithm
    to create the JWE Ciphertext value.
    Let the JWE Authentication Tag be the empty octet sequence.

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
    The JWE JSON Serialization is described in {{Section 7.2 of RFC7516}}.

## Message Decryption {#decryption}

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
    the JWE Authentication Tag.
    When using the JWE JSON Serialization,
    these components also include the base64url-encoded representation of
    the JWE AAD, along with the unencoded
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
    is described in {{Section 7.2 of RFC7516}}.

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
    or by the "crit" Header Parameter value,
    and that the values of those parameters are also understood and supported.

1.  Determine the Key Management Mode employed by the algorithm
    specified by the
    "alg" (algorithm) Header Parameter.

1.  If using Integrated Encryption, Direct Encryption, or Direct Key Agreement,
    verify that there is exactly one recipient.

1.  Verify that the JWE uses a key known to the recipient.

1.  When Direct Key Agreement or Key Agreement with Key Wrapping
    is employed, use the key agreement algorithm
    to compute the value of the agreed upon key.
    When Direct Key Agreement is employed,
    let the CEK be the agreed upon key.
    When Key Agreement with Key Wrapping is employed,
    the agreed upon key will be used to decrypt the JWE Encrypted Key.

1.  When Key Wrapping, Key Encryption,
    or Key Agreement with Key Wrapping is employed,
    decrypt the JWE Encrypted Key to produce the CEK.
    The CEK MUST have a length equal to that
    required for the content encryption algorithm.
    Note that when there are multiple recipients,
    each recipient will only be able to decrypt JWE Encrypted Key values
    that were encrypted to a key in that recipient's possession.
    It is therefore normal to only be able to decrypt one of the
    per-recipient JWE Encrypted Key values to obtain the CEK value.
    Also, see {{Section 11.5 of RFC7516}} for security considerations
    on mitigating timing attacks.

1.  When Direct Key Agreement or Direct Encryption is employed,
    verify that the JWE Encrypted Key value is an empty octet sequence.

1.  When Direct Encryption is employed,
    let the CEK be the shared symmetric key.

1.  If Integrated Encryption is not being employed,
    record whether the CEK could be successfully determined for this recipient or not.

1.  If the JWE JSON Serialization is being used and
    there are multiple recipients, repeat this process
    (steps 4-13)
    for each recipient contained in the representation.

1.  Compute the Encoded Protected Header value
    BASE64URL(UTF8(JWE Protected Header)).
    If the JWE Protected Header is not present
    (which can only happen when using the JWE JSON Serialization
    and no "protected" member is present),
    let this value be the empty string.

1.  Let the Additional Authenticated Data encryption parameter be
    ASCII(Encoded Protected Header).
    However, if a JWE AAD value is present
    (which can only be the case when using the JWE JSON Serialization),
    instead let the Additional Authenticated Data encryption parameter be
    ASCII(Encoded Protected Header || '.' || BASE64URL(JWE AAD)).

1.  If Integrated Encryption is not being employed,
    decrypt the JWE Ciphertext using the CEK, the JWE Initialization Vector,
    the Additional Authenticated Data value,
    and the JWE Authentication Tag
    (which is the Authentication Tag input to the calculation)
    using the content encryption algorithm specified in the "enc" header parameter,
    returning the decrypted plaintext and validating the JWE Authentication Tag
    in the manner specified for the algorithm,
    rejecting the input without emitting any decrypted output
    if the JWE Authentication Tag is incorrect.

1.  If Integrated Encryption is being employed,
    verify that no "enc" header parameter is present.

1.  If Integrated Encryption is being employed,
    decrypt the JWE Ciphertext
    using the specified Integrated Encryption algorithm,
    returning the decrypted plaintext
    in the manner specified for the algorithm,
    rejecting the input without emitting any decrypted output
    if the decryption fails.

1.  If a "zip" parameter was included,
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

# Distinguishing Between JWS and JWE Objects {#distinguishing}

{{Section 9 of RFC7516}} is updated to delete the last bullet, which says:

* The JOSE Header for a JWS can also be distinguished from
  the JOSE Header for a JWE by
  determining whether an
  "enc" (encryption algorithm) member exists.
  If the "enc" member exists, it is a JWE;
  otherwise, it is a JWS.

The deleted test no longer works when Integrated Encryption is used.

The other methods of distinguishing between
JSON Web Signature (JWS) {{RFC7515}} and
JSON Web Encryption (JWE) {{RFC7516}} objects continue to work.

# JWK Representations for JWE HPKE Keys

The JSON Web Key (JWK) {{RFC7517}} representations for keys
used with the JWE algorithms defined in this specification are as follows.
The valid combinations of the
"alg", "kty", and "crv" in the JWK are shown in {{ciphersuite-kty-crv}}.

| "alg" values                         | "kty" | "crv"  |
| ------------------------------------ | ----- | ------ |
| HPKE-0, HPKE-0-KE, HPKE-7, HPKE-7-KE | EC    | P-256  |
| HPKE-1, HPKE-1-KE                    | EC    | P-384  |
| HPKE-2, HPKE-2-KE                    | EC    | P-521  |
| HPKE-3, HPKE-3-KE, HPKE-4, HPKE-4-KE | OKP   | X25519 |
| HPKE-5, HPKE-5-KE, HPKE-6, HPKE-6-KE | OKP   | X448   |
{: #ciphersuite-kty-crv title="JWK Types and Curves for JWE HPKE Ciphersuites"}

Examples of JWKs for each algorithm are provided in {{test-vectors}}.

# Security Considerations

This specification uses HPKE, and the security considerations of
{{I-D.ietf-hpke-hpke}} are therefore applicable.

HPKE assumes the sender is in possession of the public key of the recipient and
HPKE JOSE makes the same assumption. Hence, some form of public key distribution
mechanism is assumed to exist but outside the scope of this document.

HPKE in Base mode does not provide proof of sender origin
as part of the HPKE KEM. PSK mode authenticates the sender
as a holder of the pre-shared key (see {{Section 9.1 of
I-D.ietf-hpke-hpke}}).

HPKE relies on a source of randomness being available on the device.
In Key Agreement with Key Wrapping mode, the CEK has to be randomly generated.
The guidance on randomness in {{RFC8937}} applies.

## Key Management

A KEM key pair used with HPKE is intended for use with a
specific mode and HPKE algorithm suite. Using the same
KEM key pair with multiple modes or multiple HPKE algorithm
suites in parallel is NOT RECOMMENDED.

In principle, such use could be supported by the HPKE key
schedule, since it takes both the suite_id variable, which
encodes the full ciphersuite, and the mode byte as inputs,
ensuring that cryptographically distinct keys are derived
for each combination of ciphersuite and mode. However, there
is no formal proof of security for this at the time of
writing; see {{Section 9.2.2 of I-D.ietf-hpke-hpke}}.

Likewise,the same key SHOULD NOT be used with both HPKE and
non-HPKE algorithms (e.g., "ECDH-ES" or "ECDH-ES+A128KW").

When using Key Encryption in a multi-recipient scenario, the
security of the content is limited by the weakest algorithm used
to encrypt the CEK.

## JWT Best Current Practices

The guidance in {{RFC8725}} about encryption is also pertinent to this specification.

RFC Editor Note: If draft-ietf-oauth-8725bis has been published as
an RFC by the time this document is processed, please update the
reference from {{RFC8725}} to the published RFC for
draft-ietf-oauth-8725bis.

#  IANA Considerations {#IANA}

## JSON Web Signature and Encryption Algorithms

The following entries are added to the IANA "JSON Web Signature and Encryption Algorithms" registry {{IANA.JOSE}} established by {{RFC7518}}:

### HPKE-0
{: toc="exclude"}

- Algorithm Name: HPKE-0
- Algorithm Description: Integrated Encryption with HPKE using DHKEM(P-256, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{int-algs}} of [[ this specification ]]
- Algorithm Analysis Documents(s): {{Section 6.1 of I-D.ietf-hpke-hpke}}

### HPKE-1
{: toc="exclude"}

- Algorithm Name: HPKE-1
- Algorithm Description: Integrated Encryption with HPKE using DHKEM(P-384, HKDF-SHA384) KEM, HKDF-SHA384 KDF, and AES-256-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{int-algs}} of [[ this specification ]]
- Algorithm Analysis Documents(s): {{Section 6.1 of I-D.ietf-hpke-hpke}}

### HPKE-2
{: toc="exclude"}

- Algorithm Name: HPKE-2
- Algorithm Description: Integrated Encryption with HPKE using DHKEM(P-521, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and AES-256-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{int-algs}} of [[ this specification ]]
- Algorithm Analysis Documents(s): {{Section 6.1 of I-D.ietf-hpke-hpke}}

### HPKE-3
{: toc="exclude"}

- Algorithm Name: HPKE-3
- Algorithm Description: Integrated Encryption with HPKE using DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{int-algs}} of [[ this specification ]]
- Algorithm Analysis Documents(s): {{Section 6.1 of I-D.ietf-hpke-hpke}}

### HPKE-4
{: toc="exclude"}

- Algorithm Name: HPKE-4
- Algorithm Description: Integrated Encryption with HPKE using DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and ChaCha20Poly1305 AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{int-algs}} of [[ this specification ]]
- Algorithm Analysis Documents(s): {{Section 6.1 of I-D.ietf-hpke-hpke}}

### HPKE-5
{: toc="exclude"}

- Algorithm Name: HPKE-5
- Algorithm Description: Integrated Encryption with HPKE using DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and AES-256-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{int-algs}} of [[ this specification ]]
- Algorithm Analysis Documents(s): {{Section 6.1 of I-D.ietf-hpke-hpke}}

### HPKE-6
{: toc="exclude"}

- Algorithm Name: HPKE-6
- Algorithm Description: Integrated Encryption with HPKE using DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and ChaCha20Poly1305 AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{int-algs}} of [[ this specification ]]
- Algorithm Analysis Documents(s): {{Section 6.1 of I-D.ietf-hpke-hpke}}

### HPKE-7
{: toc="exclude"}

- Algorithm Name: HPKE-7
- Algorithm Description: Integrated Encryption with HPKE using DHKEM(P-256, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-256-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{int-algs}} of [[ this specification ]]
- Algorithm Analysis Documents(s): {{Section 6.1 of I-D.ietf-hpke-hpke}}

### HPKE-0-KE
{: toc="exclude"}

- Algorithm Name: HPKE-0-KE
- Algorithm Description: Key Encryption with HPKE using DHKEM(P-256, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{ke-algs}} of [[ this specification ]]
- Algorithm Analysis Documents(s): {{Section 5 of I-D.ietf-hpke-hpke}}

### HPKE-1-KE
{: toc="exclude"}

- Algorithm Name: HPKE-1-KE
- Algorithm Description: Key Encryption with HPKE using DHKEM(P-384, HKDF-SHA384) KEM, HKDF-SHA384 KDF, and AES-256-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{ke-algs}} of [[ this specification ]]
- Algorithm Analysis Documents(s): {{Section 5 of I-D.ietf-hpke-hpke}}

### HPKE-2-KE
{: toc="exclude"}

- Algorithm Name: HPKE-2-KE
- Algorithm Description: Key Encryption with HPKE using DHKEM(P-521, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and AES-256-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{ke-algs}} of [[ this specification ]]
- Algorithm Analysis Documents(s): {{Section 5 of I-D.ietf-hpke-hpke}}

### HPKE-3-KE
{: toc="exclude"}

- Algorithm Name: HPKE-3-KE
- Algorithm Description: Key Encryption with HPKE using DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{ke-algs}} of [[ this specification ]]
- Algorithm Analysis Documents(s): {{Section 5 of I-D.ietf-hpke-hpke}}

### HPKE-4-KE
{: toc="exclude"}

- Algorithm Name: HPKE-4-KE
- Algorithm Description: Key Encryption with HPKE using DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and ChaCha20Poly1305 AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{ke-algs}} of [[ this specification ]]
- Algorithm Analysis Documents(s): {{Section 5 of I-D.ietf-hpke-hpke}}

### HPKE-5-KE
{: toc="exclude"}

- Algorithm Name: HPKE-5-KE
- Algorithm Description: Key Encryption with HPKE using DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and AES-256-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{ke-algs}} of [[ this specification ]]
- Algorithm Analysis Documents(s): {{Section 5 of I-D.ietf-hpke-hpke}}

### HPKE-6-KE
{: toc="exclude"}

- Algorithm Name: HPKE-6-KE
- Algorithm Description: Key Encryption with HPKE using DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and ChaCha20Poly1305 AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{ke-algs}} of [[ this specification ]]
- Algorithm Analysis Documents(s): {{Section 5 of I-D.ietf-hpke-hpke}}

### HPKE-7-KE
{: toc="exclude"}

- Algorithm Name: HPKE-7-KE
- Algorithm Description: Key Encryption with HPKE using DHKEM(P-256, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-256-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{ke-algs}} of [[ this specification ]]
- Algorithm Analysis Documents(s): {{Section 5 of I-D.ietf-hpke-hpke}}

## JSON Web Signature and Encryption Header Parameters

The following entries are added to the IANA "JSON Web Signature and Encryption Header Parameters" registry {{IANA.JOSE}}:

### ek
{: toc="exclude"}

- Header Parameter Name: "ek"
- Header Parameter Description: A base64url-encoded encapsulated secret, as defined in {{Section 5 of I-D.ietf-hpke-hpke}}
- Header Parameter Usage Location(s): JWE
- Change Controller: IETF
- Specification Document(s): {{encapsulated-secrets}} of [[ this specification ]]

### psk_id
{: toc="exclude"}

- Header Parameter Name: "psk_id"
- Header Parameter Description: A base64url-encoded key identifier (kid) for the pre-shared key, as defined in {{Section 5.1.2 of I-D.ietf-hpke-hpke}}
- Header Parameter Usage Location(s): JWE
- Change Controller: IETF
- Specification Document(s): {{overview}} of [[ this specification ]]

# Summary of Updates to RFC 7516 (JWE)

This specification updates JSON Web Encryption (JWE) {{RFC7516}} as follows:

- Adds the Integrated Encryption Key Management Mode and correspondingly
  updates the Key Management Mode definition ({{terminology}}).

- Updates the "enc" header parameter to be absent when
  Integrated Encryption is used in ({{overview}}).

- Replaces the Message Encryption procedure ({{encryption}}).

- Replaces the Message Decryption procedure ({{decryption}}).

- Updates the methods for distinguishing between JWS and JWE objects
  ({{distinguishing}}).

--- back

# Test Vectors {#test-vectors}

This appendix provides test vectors for each algorithm defined in this document.
For each algorithm, a private JWK, a Flattened JWE JSON Serialization example with
Additional Authenticated Data, and a JWE Compact Serialization example are provided.
Long lines in the examples are folded using the single backslash strategy from
{{RFC8792}}. Before using a folded example as a test vector, remove the RFC 8792
header and unfold the lines according to that strategy.
The complete unfolded vector set is available as `examples/jose-vectors.json`
in the [repository](https://github.com/ietf-wg-jose/draft-ietf-jose-hpke-encrypt)
for this document.

<!-- begin:test-vectors ; see README for regeneration instructions, do not edit -->

## HPKE-0
{: toc="exclude"}

~~~ json
{::include examples/jwks/HPKE-0.json}
~~~
{: title="HPKE-0 Private JWK" post="fold69hardsmart2dry"}

~~~ json
{::include examples/jwe/HPKE-0-flattened.json}
~~~
{: title="HPKE-0 Flattened JWE JSON Serialization" post="fold69hardsmart2dry"}

~~~
{::include examples/jwe/HPKE-0-compact.txt}
~~~
{: title="HPKE-0 JWE Compact Serialization" post="fold69hardleftdry"}

## HPKE-0-KE
{: toc="exclude"}

~~~ json
{::include examples/jwks/HPKE-0-KE.json}
~~~
{: title="HPKE-0-KE Private JWK" post="fold69hardsmart2dry"}

~~~ json
{::include examples/jwe/HPKE-0-KE-flattened.json}
~~~
{: title="HPKE-0-KE Flattened JWE JSON Serialization" post="fold69hardsmart2dry"}

~~~
{::include examples/jwe/HPKE-0-KE-compact.txt}
~~~
{: title="HPKE-0-KE JWE Compact Serialization" post="fold69hardleftdry"}

## HPKE-1
{: toc="exclude"}

~~~ json
{::include examples/jwks/HPKE-1.json}
~~~
{: title="HPKE-1 Private JWK" post="fold69hardsmart2dry"}

~~~ json
{::include examples/jwe/HPKE-1-flattened.json}
~~~
{: title="HPKE-1 Flattened JWE JSON Serialization" post="fold69hardsmart2dry"}

~~~
{::include examples/jwe/HPKE-1-compact.txt}
~~~
{: title="HPKE-1 JWE Compact Serialization" post="fold69hardleftdry"}

## HPKE-1-KE
{: toc="exclude"}

~~~ json
{::include examples/jwks/HPKE-1-KE.json}
~~~
{: title="HPKE-1-KE Private JWK" post="fold69hardsmart2dry"}

~~~ json
{::include examples/jwe/HPKE-1-KE-flattened.json}
~~~
{: title="HPKE-1-KE Flattened JWE JSON Serialization" post="fold69hardsmart2dry"}

~~~
{::include examples/jwe/HPKE-1-KE-compact.txt}
~~~
{: title="HPKE-1-KE JWE Compact Serialization" post="fold69hardleftdry"}

## HPKE-2
{: toc="exclude"}

~~~ json
{::include examples/jwks/HPKE-2.json}
~~~
{: title="HPKE-2 Private JWK" post="fold69hardsmart2dry"}

~~~ json
{::include examples/jwe/HPKE-2-flattened.json}
~~~
{: title="HPKE-2 Flattened JWE JSON Serialization" post="fold69hardsmart2dry"}

~~~
{::include examples/jwe/HPKE-2-compact.txt}
~~~
{: title="HPKE-2 JWE Compact Serialization" post="fold69hardleftdry"}

## HPKE-2-KE
{: toc="exclude"}

~~~ json
{::include examples/jwks/HPKE-2-KE.json}
~~~
{: title="HPKE-2-KE Private JWK" post="fold69hardsmart2dry"}

~~~ json
{::include examples/jwe/HPKE-2-KE-flattened.json}
~~~
{: title="HPKE-2-KE Flattened JWE JSON Serialization" post="fold69hardsmart2dry"}

~~~
{::include examples/jwe/HPKE-2-KE-compact.txt}
~~~
{: title="HPKE-2-KE JWE Compact Serialization" post="fold69hardleftdry"}

## HPKE-3
{: toc="exclude"}

~~~ json
{::include examples/jwks/HPKE-3.json}
~~~
{: title="HPKE-3 Private JWK" post="fold69hardsmart2dry"}

~~~ json
{::include examples/jwe/HPKE-3-flattened.json}
~~~
{: title="HPKE-3 Flattened JWE JSON Serialization" post="fold69hardsmart2dry"}

~~~
{::include examples/jwe/HPKE-3-compact.txt}
~~~
{: title="HPKE-3 JWE Compact Serialization" post="fold69hardleftdry"}

## HPKE-3-KE
{: toc="exclude"}

~~~ json
{::include examples/jwks/HPKE-3-KE.json}
~~~
{: title="HPKE-3-KE Private JWK" post="fold69hardsmart2dry"}

~~~ json
{::include examples/jwe/HPKE-3-KE-flattened.json}
~~~
{: title="HPKE-3-KE Flattened JWE JSON Serialization" post="fold69hardsmart2dry"}

~~~
{::include examples/jwe/HPKE-3-KE-compact.txt}
~~~
{: title="HPKE-3-KE JWE Compact Serialization" post="fold69hardleftdry"}

## HPKE-4
{: toc="exclude"}

~~~ json
{::include examples/jwks/HPKE-4.json}
~~~
{: title="HPKE-4 Private JWK" post="fold69hardsmart2dry"}

~~~ json
{::include examples/jwe/HPKE-4-flattened.json}
~~~
{: title="HPKE-4 Flattened JWE JSON Serialization" post="fold69hardsmart2dry"}

~~~
{::include examples/jwe/HPKE-4-compact.txt}
~~~
{: title="HPKE-4 JWE Compact Serialization" post="fold69hardleftdry"}

## HPKE-4-KE
{: toc="exclude"}

~~~ json
{::include examples/jwks/HPKE-4-KE.json}
~~~
{: title="HPKE-4-KE Private JWK" post="fold69hardsmart2dry"}

~~~ json
{::include examples/jwe/HPKE-4-KE-flattened.json}
~~~
{: title="HPKE-4-KE Flattened JWE JSON Serialization" post="fold69hardsmart2dry"}

~~~
{::include examples/jwe/HPKE-4-KE-compact.txt}
~~~
{: title="HPKE-4-KE JWE Compact Serialization" post="fold69hardleftdry"}

## HPKE-5
{: toc="exclude"}

~~~ json
{::include examples/jwks/HPKE-5.json}
~~~
{: title="HPKE-5 Private JWK" post="fold69hardsmart2dry"}

~~~ json
{::include examples/jwe/HPKE-5-flattened.json}
~~~
{: title="HPKE-5 Flattened JWE JSON Serialization" post="fold69hardsmart2dry"}

~~~
{::include examples/jwe/HPKE-5-compact.txt}
~~~
{: title="HPKE-5 JWE Compact Serialization" post="fold69hardleftdry"}

## HPKE-5-KE
{: toc="exclude"}

~~~ json
{::include examples/jwks/HPKE-5-KE.json}
~~~
{: title="HPKE-5-KE Private JWK" post="fold69hardsmart2dry"}

~~~ json
{::include examples/jwe/HPKE-5-KE-flattened.json}
~~~
{: title="HPKE-5-KE Flattened JWE JSON Serialization" post="fold69hardsmart2dry"}

~~~
{::include examples/jwe/HPKE-5-KE-compact.txt}
~~~
{: title="HPKE-5-KE JWE Compact Serialization" post="fold69hardleftdry"}

## HPKE-6
{: toc="exclude"}

~~~ json
{::include examples/jwks/HPKE-6.json}
~~~
{: title="HPKE-6 Private JWK" post="fold69hardsmart2dry"}

~~~ json
{::include examples/jwe/HPKE-6-flattened.json}
~~~
{: title="HPKE-6 Flattened JWE JSON Serialization" post="fold69hardsmart2dry"}

~~~
{::include examples/jwe/HPKE-6-compact.txt}
~~~
{: title="HPKE-6 JWE Compact Serialization" post="fold69hardleftdry"}

## HPKE-6-KE
{: toc="exclude"}

~~~ json
{::include examples/jwks/HPKE-6-KE.json}
~~~
{: title="HPKE-6-KE Private JWK" post="fold69hardsmart2dry"}

~~~ json
{::include examples/jwe/HPKE-6-KE-flattened.json}
~~~
{: title="HPKE-6-KE Flattened JWE JSON Serialization" post="fold69hardsmart2dry"}

~~~
{::include examples/jwe/HPKE-6-KE-compact.txt}
~~~
{: title="HPKE-6-KE JWE Compact Serialization" post="fold69hardleftdry"}

## HPKE-7
{: toc="exclude"}

~~~ json
{::include examples/jwks/HPKE-7.json}
~~~
{: title="HPKE-7 Private JWK" post="fold69hardsmart2dry"}

~~~ json
{::include examples/jwe/HPKE-7-flattened.json}
~~~
{: title="HPKE-7 Flattened JWE JSON Serialization" post="fold69hardsmart2dry"}

~~~
{::include examples/jwe/HPKE-7-compact.txt}
~~~
{: title="HPKE-7 JWE Compact Serialization" post="fold69hardleftdry"}

## HPKE-7-KE
{: toc="exclude"}

~~~ json
{::include examples/jwks/HPKE-7-KE.json}
~~~
{: title="HPKE-7-KE Private JWK" post="fold69hardsmart2dry"}

~~~ json
{::include examples/jwe/HPKE-7-KE-flattened.json}
~~~
{: title="HPKE-7-KE Flattened JWE JSON Serialization" post="fold69hardsmart2dry"}

~~~
{::include examples/jwe/HPKE-7-KE-compact.txt}
~~~
{: title="HPKE-7-KE JWE Compact Serialization" post="fold69hardleftdry"}

<!-- end:test-vectors -->

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
Deb Cooley,
and
Sebastian Stenzel
for their contributions to the specification.

Thanks to Peter Yee for the Genart review.

# Document History
{: numbered="false"}

-17

* Clarified in Section 3 that only Integrated Encryption is newly
  defined; other Key Management Modes are from {{RFC7516}}.
* Added explanation that Integrated Encryption corresponds to the
  Single-Shot API in {{Section 6.1 of I-D.ietf-hpke-hpke}}.
* Renamed "Flattened JWE JSON Serialization Example" to
  "JWE JSON Serialization Example".
* Added note explaining HPKE-7/HPKE-7-KE pairing rationale.
* Added qualifying clause to step 9 of Message Encryption and
  step 13 of Message Decryption regarding multiple recipients.
* Updated authentication wording in Security Considerations to use
  HPKE spec terminology "proof of sender origin".
* Replaced RFC4086 with {{RFC8937}}.
* Upgraded SHOULD NOT to MUST NOT for key reuse across Key
  Encryption and Integrated Encryption modes.
* Added RFC Editor note regarding draft-ietf-oauth-8725bis.
* Updated Algorithm Analysis field in IANA registrations to point
  to specific sections of {{I-D.ietf-hpke-hpke}}.
* Moved IANA.JOSE and IANA.HPKE to informative references.

-16

* Change uses of Key Establishment Mode to Key Management Mode to align with JWE terminology.

-15

* Defined the Integrated Encryption Key Establishment Mode
  and updated JWE to enable its use.
* Specified distinct algorithms for use with Key Encryption and Integrated Encryption
  so that they are fully-specified.
* Updated the Message Encryption and Message Decryption procedures from JWE.
* Said that JWS and JWE objects can no longer be distinguished by the presence of
  an "enc" header parameter.
* Many editorial improvements.

-14

* Added HPKE-7.
* Update to Recipient_structure.
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

* Added the Recipient_structure

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
