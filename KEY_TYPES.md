# Supported Key Types

A practical rule of thumb is: use RSA for maximum compatibility, EC for efficient mainstream asymmetric crypto, OKP for modern asymmetric crypto in new systems, and oct only when a shared secret is appropriate and tightly controlled.

# RSA

`RSA` stands for Rivest–Shamir–Adleman, the surnames of the three researchers who described the algorithm. `RSA` is a traditional asymmetric key type based on large integer arithmetic. In JWK/JWKS, it uses `n` (modulus) and `e` (public exponent). It is commonly used for signatures such as `RS256` and `PS256`, and historically for encryption as well. You would use RSA when you need broad compatibility with older identity providers, libraries, enterprise systems, or legacy PKI tooling. Its main advantage is ecosystem support; its drawbacks are larger key sizes and generally slower performance than modern elliptic-curve options.

## Sample RSA JWKS

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "example-rsa-key-1",
      "use": "sig",
      "alg": "RS256",
      "n": "siFKEakQYFWetyiMprTlLh6WiAbNvRAlQMlCYx7i6TseIw8Tk4q33jBzcdJkpQ7YszGDc1u-cFj1mG-2G9_POTB6sQMp2xmAcA6p6Th-lN1qjR--7df4ryw8NXPmCM2RVn0ufS5LPvtgCR9F468qV7fMaAW9HGngj79p5M6xZ2jbB1hCVVok547Eebi9ZWF7eS9heZJXCWt_ameG2mdeeVKSTuEk9ZGpN5ne0jcUdmp1pla4YOk2Qvt5HBiuxZhVweb_HTX20a4uUVHN6j9l0gxp3xpwNFMZm8fMNMbf_MkyNtnsOqEqeoYuEwOQOdi_c3nsc7OzU-1HXnCR6icAHQ",
      "e": "AQAB"
    }
  ]
}
```

## Matching RSA Public Key in PEM Format

```pem
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsiFKEakQYFWetyiMprTl
Lh6WiAbNvRAlQMlCYx7i6TseIw8Tk4q33jBzcdJkpQ7YszGDc1u+cFj1mG+2G9/P
OTB6sQMp2xmAcA6p6Th+lN1qjR++7df4ryw8NXPmCM2RVn0ufS5LPvtgCR9F468q
V7fMaAW9HGngj79p5M6xZ2jbB1hCVVok547Eebi9ZWF7eS9heZJXCWt/ameG2mde
eVKSTuEk9ZGpN5ne0jcUdmp1pla4YOk2Qvt5HBiuxZhVweb/HTX20a4uUVHN6j9l
0gxp3xpwNFMZm8fMNMbf/MkyNtnsOqEqeoYuEwOQOdi/c3nsc7OzU+1HXnCR6icA
HQIDAQAB
-----END PUBLIC KEY-----
```

## Notes

- `kty: "RSA"` means the key material is carried in:
  - `n` = modulus
  - `e` = public exponent
- In this sample:
  - `e = "AQAB"` = 65537
- The JWK uses **Base64URL** encoding for `n` and `e`.
- The PEM uses **standard Base64** and wraps the key in ASN.1 `SubjectPublicKeyInfo`.

## Conceptual Mapping

```text
JWK:  n + e
   -> RSA public key
   -> ASN.1 SubjectPublicKeyInfo
   -> Base64
   -> PEM
```

## PEM to JWK

Given the PEM, a parser can derive:

- `kty = RSA`
- `n = siFKEakQYFWetyiMprTlLh6WiAbNvRAlQMlCYx7i6TseIw8Tk4q33jBzcdJkpQ7YszGDc1u-cFj1mG-2G9_POTB6sQMp2xmAcA6p6Th-lN1qjR--7df4ryw8NXPmCM2RVn0ufS5LPvtgCR9F468qV7fMaAW9HGngj79p5M6xZ2jbB1hCVVok547Eebi9ZWF7eS9heZJXCWt_ameG2mdeeVKSTuEk9ZGpN5ne0jcUdmp1pla4YOk2Qvt5HBiuxZhVweb_HTX20a4uUVHN6j9l0gxp3xpwNFMZm8fMNMbf_MkyNtnsOqEqeoYuEwOQOdi_c3nsc7OzU-1HXnCR6icAHQ`
- `e = AQAB`

because the PEM contains the RSA public modulus and exponent in DER form.

## OpenSSL Check

This PEM should parse correctly with:

```bash
openssl pkey -pubin -in rsa-public.pem -text -noout
```

# EC 

`EC` stands for Elliptic Curve and represents asymmetric keys defined by a point on a named curve, using `crv`, `x`, and `y`. It is commonly used with algorithms like `ES256`, `ES384`, and `ES512`. You would use EC when you want smaller keys and signatures than RSA while still staying within very widely supported standards, especially for modern OIDC, JWT, and TLS-related systems. It is often a strong default when both sides support it and you want good efficiency without moving to newer curve families like Ed25519.

## Sample EC JWKS

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "kid": "example-ec-key-1",
      "use": "sig",
      "alg": "ES256",
      "x": "HHlYLSNa8j_z3_hlpXrpHkpWm_m5NectQi6j_c5m-WY",
      "y": "2A5BUVTJBM7aJchB4ZaCNV648sbK0LWA1sGlcUKFYNo"
    }
  ]
}
```

## Matching EC Public Key in PEM Format

```pem
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHHlYLSNa8j/z3/hlpXrpHkpWm/m5
NectQi6j/c5m+WbYDkFRVMkEztolyEHhloI1XrjyxsrQtYDWwaVxQoVg2g==
-----END PUBLIC KEY-----
```

## Notes

- `crv: "P-256"` maps to the NIST P-256 / secp256r1 curve.
- `x` and `y` are the affine public point coordinates, encoded as **Base64URL without padding**.
- The PEM body is **standard Base64**, not Base64URL.
- This PEM corresponds to the same public key as the JWK above.

## Why PEM and JWK Look Different

- JWK uses separate fields:
  - `x`
  - `y`
  - `crv`
- PEM wraps the same public key into an ASN.1 `SubjectPublicKeyInfo` structure and then Base64-encodes it.

Conceptually:

```text
JWK:  crv + x + y
   -> EC point = 04 || X || Y
   -> ASN.1 SubjectPublicKeyInfo
   -> Base64
   -> PEM
```

## OpenSSL Check

This PEM should parse with OpenSSL:

```bash
openssl pkey -pubin -in ec-public.pem -text -noout
```

## Mapping Back from PEM to JWK

Given this PEM, a parser can derive:

- `crv = P-256`
- `x = HHlYLSNa8j_z3_hlpXrpHkpWm_m5NectQi6j_c5m-WY`
- `y = 2A5BUVTJBM7aJchB4ZaCNV648sbK0LWA1sGlcUKFYNo`

because the PEM contains the EC public point in uncompressed form:

```text
04 || X || Y
```

# OKP 

`OKP` stands for Octet Key Pair and is used for modern curve-based key types such as `Ed25519` and `X25519`. In JWK form it typically uses `crv` and `x`. For signatures, the main example is `Ed25519` with EdDSA; for key agreement, `X25519` is common. You would use OKP when you want modern, compact, high-performance cryptography with simpler key handling than traditional EC. It is an excellent choice for new systems, but compatibility can be narrower than RSA or classic EC depending on the platform, library, or identity provider.

## Sample OKP JWKS (Ed25519)

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "example-okp-key-1",
      "use": "sig",
      "alg": "EdDSA",
      "x": "y3XQ-VuL7Q0LCSKgskZOkVu8g3gC17ZGXm5uj8xt4nQ"
    }
  ]
}
```

## Matching OKP Public Key in PEM Format

```pem
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAy3XQ+VuL7Q0LCSKgskZOkVu8g3gC17ZGXm5uj8xt4nQ=
-----END PUBLIC KEY-----
```

## Notes for OKP

- `kty: "OKP"` means Octet Key Pair.
- `crv: "Ed25519"` identifies the curve / algorithm family.
- `x` is the raw 32-byte Ed25519 public key, encoded as **Base64URL without padding**.
- The PEM is the same public key wrapped as ASN.1 `SubjectPublicKeyInfo` and encoded as standard Base64.

Conceptually:

```text
JWK: x
 -> raw Ed25519 public key bytes
 -> ASN.1 SubjectPublicKeyInfo
 -> Base64
 -> PEM
```

You can validate the PEM with:

```bash
openssl pkey -pubin -in okp-public.pem -text -noout
```

---

## Sample oct JWKS

```json
{
  "keys": [
    {
      "kty": "oct",
      "kid": "example-oct-key-1",
      "use": "sig",
      "alg": "HS256",
      "k": "nvCOlEaAhu6n5EiKOtZePbfZhRVna2PaRSfyN-jEYG0"
    }
  ]
}
```

# oct

`oct` stands for octet sequence, which is just symmetric key material represented by `k`. It is used with shared-secret algorithms such as `HS256`, `HS384`, and `HS512`, and also some symmetric encryption scenarios. You would use oct when both parties can safely share and protect the same secret, such as service-to-service communication under your own control. It is simple and fast, but it is usually a poor fit for public JWKS endpoints because symmetric keys must remain secret and cannot be broadly distributed the way public keys can.

## Notes for oct

- `kty: "oct"` means a symmetric octet sequence key.
- `k` is the shared secret, encoded as **Base64URL without padding**.
- This example is appropriate for algorithms like:
  - `HS256`
  - `HS384`
  - `HS512`
  - or symmetric JWE algorithms, depending on usage

---

## Why There Is No Standard PEM for oct

Unlike `RSA`, `EC`, or `OKP`, an `oct` key is not a public key. It is just secret bytes:

```text
k
```

So there is no standard equivalent of:

```pem
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
```

for `oct`.

That is because:

- there is no public/private split
- there is no ASN.1 public-key structure to wrap
- most systems store symmetric keys as raw bytes, Base64, JWK, or in a keystore / secret manager

---

## If You Need the oct Key Rendered as Raw Secret Material

Here is the same `oct` key in standard Base64:

```text
nvCOlEaAhu6n5EiKOtZePbfZhRVna2PaRSfyN+jEYG0=
```

And in hex:

```text
9ef08e94468086eea7e4488a3ad65e3db7d98515676b63da4527f237e8c4606d
```

These are just alternate encodings of the same symmetric key.

---

## Summary

### OKP
- JWK public-key fields:
  - `kty`
  - `crv`
  - `x`
- PEM available:
  - yes

### oct
- JWK key fields:
  - `kty`
  - `k`
- PEM available:
  - no standard public-key PEM form exists
