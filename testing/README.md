# BBS+ Issuance Prototype — Technical Demonstration

This directory contains `demo.py`, which provides a complete, end-to-end execution of the BBS+ verifiable credential protocol. It showcases every major cryptographic interaction, from authority registration to selective disclosure and re-issuance.

## Running the Demo

To execute the demonstration and see the full protocol flow:

```bash
# From the project root
export PYTHONPATH=src
python3 testing/demo.py
```

---

## Full Protocol Execution Log

The following log represents a complete round-trip of the system. It highlights the structured, human-readable reporting implemented in this session to provide transparency into the cryptographic payloads.

### 1. Authority Initialization & Registry Synchronization
The demonstration begins with the **Issuer** announcing its authoritative metadata to the **Registry**. Subsequently, both the **Holder** and **Verifier** synchronize their local caches to ensure they have the necessary public keys for verification.

```text
=== Registering issuer ===
Request 1:

==================================================
             REGISTER ISSUER DETAILS              
==================================================
Issuer Name: VeryCredible-University

==================================================
                 ISSUER PUBLIC DATA                
==================================================
Issuer Name:    VeryCredible-University
Public Key:     a91707aa02...09de3b8be5
Revocation:     2 bits
Epoch Size:     7 days
Valid For:      7 weeks
==================================================


Response 1:

==================================================
              ISSUER DETAILS RESPONSE              
==================================================

==================================================
                 ISSUER PUBLIC DATA                
==================================================
Issuer Name:    VeryCredible-University
Public Key:     a91707aa02...09de3b8be5
Revocation:     2 bits
Epoch Size:     7 days
Valid For:      7 weeks
==================================================

=== Done ===

=== Fetching bulk issuer details for verifier ===
Request 2:

==================================================
            BULK ISSUER DETAILS REQUEST            
==================================================
Type: BULK_ISSUER_DETAILS_REQUEST
==================================================

Response 2:

==================================================
            BULK ISSUER DETAILS RESPONSE           
==================================================
Count: 1
  - VeryCredible-University (a91707aa02...)
==================================================

=== Done ===

=== Fetching bulk issuer details for holder ===
Request 3:

==================================================
            BULK ISSUER DETAILS REQUEST            
==================================================
Type: BULK_ISSUER_DETAILS_REQUEST
==================================================

Response 3:

==================================================
            BULK ISSUER DETAILS RESPONSE           
==================================================
Count: 1
  - VeryCredible-University (a91707aa02...)
==================================================

=== Done ===
```

### 2. Multi-Round Blind Issuance
The Holder requests a new credential. This involves a four-step handshake ensuring the Issuer never sees the Holder's secret attributes (like the `LinkSecret`).

1. **VCIssuanceRequest**: Initiation.
2. **FreshnessUpdateResponse**: Issuer provides a 32-byte challenge nonce.
3. **BlindSignRequest**: Holder provides a Pedersen commitment and a Zero-Knowledge proof of its validity, bound to the nonce.
4. **ForwardVCResponse**: Issuer returns the blind signature attached to a VC skeleton.

```text
=== Requesting credential ===
Request 4:

==================================================
                     ISSUANCE                     
==================================================
Type: ISSUANCE
==================================================

Response 4:

==================================================
                 FRESHNESS UPDATE                 
==================================================
Nonce: 6c3dec8a6313567648ba43eea89fa8b8fe55739142ec84be9a8fb559f5729467
==================================================

Response 5:

==================================================
                 BLIND SIGN REQUEST                
==================================================
Total Messages:  7
Commitment:      875960aa65df1f3ec22e...
Proof:           875960aa65df1f3ec22e...

Revealed Attributes:
  - name: Ilya
  - id: 123456
  - age: 23
  - validUntil: PLACE-HOLDER-VALIDUNTIL
  - revocationMaterial: PLACE-HOLDER-REVOCATION
  - metaHash: PLACE-HOLDER-METAHASH

Blinded Indices:
  3
==================================================

Response 6:

==================================================
               FORWARD VC RESPONSE                
==================================================
Verifiable Credential:
{
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://example.org/contexts/student-card-v1"
    ],
    "type": [
        "VerifiableCredential",
        "MockCredential"
    ],
    "issuer": "VeryCredible-University",
    "credentialSubject": {
        "name": "Ilya",
        "id": "123456",
        "age": "23",
        "LinkSecret": "",
        "validUntil": "2026-05-28T00:00:00Z",
        "revocationMaterial": "123",
        "metaHash": "f5cae90d60d92d9f69e50f627dd14b3854e1636cd363558ef3e0bd36a8beec60"
    },
    "proof": "98d8f1cdff505c9f66b6644982ad66d27e283b1d3403f7115c02f48233d07bb97dc732f45aa282b56695916186967d7f4acdaf05bd9d79b191645a5786006678e57c5d1f5f758b4187dad9c1622f6b2555938d728398a0b3ee55708225bbdcceaba46b008558ceb97ee6c7f53421c1a7"
}
==================================================

=== Done ===
```

### 3. Selective Disclosure (ZKP Presentation)
The Holder generates a Verifiable Presentation in response to a Verifier's request. Only the requested attributes are disclosed; others remain cryptographically hidden by the Zero-Knowledge Proof.

```text
=== Requesting presentation ===
Request 7:

==================================================
                    VP REQUEST                    
==================================================
Nonce: ce6b02d931995770f882f29569bfa58c69cc27357fda2d2b61a79dd9149049eb

Requested Attributes:
  - name
  - id
  - validUntil
==================================================

Response 7:

==================================================
               FORWARD VP RESPONSE                
==================================================
Issuer Public Key: a91707aa02ecf846983c...

Verifiable Presentation:
{
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://example.org/contexts/student-card-v1"
    ],
    "type": [
        "VerifiablePresentation"
    ],
    "verifiableCredential": {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://example.org/contexts/student-card-v1"
        ],
        "type": [
            "VerifiableCredential",
            "MockCredential"
        ],
        "issuer": "VeryCredible-University",
        "credentialSubject": {
            "name": "Ilya",
            "id": "123456",
            "validUntil": "2026-05-28T00:00:00Z"
        },
        "proof": "000713b22551cec2a08367c3515d4a1aef257f588e799ff5162be296851dcc64107515f375689fff90c0d452f6b963c24d839a8ccac29be232b849300f9565f2c61a5d453ce099849a8bfeba9b5f990bd265300f5a0fcb0356c4ef86947fc7aef01a1cab45b3bfd36d546f408fb25f088c5d4af33f3bc1321ee9406579f0276459e7c75e644ac5e417707976eb18da39f7a3eb00000074b279aa14fe33e091d06eb64d9b62075503a8544ec75183d6a9244da17e28f13010394dd89126ff72eb2300af4b329d470000000268dba8bc2cedcacec0ce0db322bd2cf6b0803c84a2d464a83a5aa895cf88fc9961ee4e5c131c7599f9213cfbcd81376149a35c27cf338aaa90ad234edb0d4b4a9869a8d28c5cc1276b1cf1866d805fbe20c4a24bbe4054e4e273930b1bc34c3f2fe2d07c3912ab8acb90aed8a8de60740000000613eb8ec405453f9b5e5020e5f36c5e977b47b83700f9d053d666dbc28fcad59c211265516dfe6afa02517b65e520f88f62b9ea4d6ff167d69f71a13c9665cd9b5396957a9e376a30f133b000c210f2eceb7b9e364e88a54624c2361493863f004622a595c4a5e06957239ef5db6831b6e4aad390bf0dc434dc5358f2f1978e0c3d13ba85ddd6d3b040bcdd3e074bcfbac43b77bbd48158250e43a78a1befc7966eb0973ac8624a68ba99c7f95c370b25c6c92b08544861bf61f7123ae2ac37a8"
    }
}
==================================================

Valid:  True
Disclosed messages:  {'name': 'Ilya', 'id': '123456', 'validUntil': '2026-05-28T00:00:00Z'}
=== Done ===
```

### 4. Credential Re-issuance (Renewal)
The Holder renews a credential near its epoch boundary. This involves presenting a ZKP of the old credential to bind the session and providing a *new* blinded commitment for the renewed credential.

```text
=== Requesting reissuance ===
Request 8:

==================================================
                   RE ISSUANCE                    
==================================================
Type: RE_ISSUANCE
==================================================

Response 8:

==================================================
                 FRESHNESS UPDATE                 
==================================================
Nonce: 6ec85b7515eb3b5ac7140f57b2b3bab4d24fd99b4dd09b791618bf76fa7c567c
==================================================

Response 9:

==================================================
            FORWARD VP AND COMMITMENT             
==================================================
Total Messages:  7
Commitment:      96e7bab389c122712a92...
PoK Proof:       96e7bab389c122712a92...

Verifiable Presentation:
{
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://example.org/contexts/student-card-v1"
    ],
    "type": [
        "VerifiablePresentation"
    ],
    "verifiableCredential": {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://example.org/contexts/student-card-v1"
        ],
        "type": [
            "VerifiableCredential",
            "MockCredential"
        ],
        "issuer": "VeryCredible-University",
        "credentialSubject": {
            "name": "Ilya",
            "id": "123456",
            "age": "23",
            "validUntil": "2026-05-28T00:00:00Z",
            "revocationMaterial": "123",
            "metaHash": "f5cae90d60d92d9f69e50f627dd14b3854e1636cd363558ef3e0bd36a8beec60"
        },
        "proof": "0007778d15419b86588a532f4e7853432a3b9e79b09e6b633d144c1298bb2f041a8a73ed3015557fd3115c0b411bd3e2c5d46aa202221f6b7976709c46eed70ec49f17263a5581d759bc132678bcc4e8a2d53b585c2e0fe8c9f834d9da4fbcff73fa40a0a409b8df9d528b1575563ab5fc8bc47cf4e5a6c02bb530dd389924cc84152fb169fd382e33ea36565e0834bc0b72df000000748a20b03ba800081a9b3ba0616be966640c18353713a9700826e9d4e38335a54ffab4c51b835be07a4f8d82ed4624ba820000000217013d4c4953563f6e8ffc33a19a1d74a2722469c1cdc498e1ae53e53118d2295c159aef456b437fe91ea25ec9e721b47f5d716f23a9365a15fb5c6678e10e4b9329123406c9256bf81328071888e006153dacbbf884c0d3b708194ebe874077ac4a1a437d2d4c2827f67c03f8fc2efb000000030effb394ede201fc03870426449e8019c4c3dff79db442dfaaec8dab9bafef5c1522c084dc7e284f1d8b5479355286a528a49f4fb9aa10647bafb1c30d4186786d07595bbae42d04b1e5ff1508bef0ee3a1eebd982e926faf346f95bffa07de2"
    }
}

Revealed Attributes (for re-issuance):
  - name: Ilya
  - id: 123456
  - age: 23
  - validUntil: PLACE-HOLDER-VALIDUNTIL
  - revocationMaterial: PLACE-HOLDER-REVOCATION
  - metaHash: PLACE-HOLDER-METAHASH
==================================================

Response 10:

==================================================
               FORWARD VC RESPONSE                
==================================================
Verifiable Credential:
{
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://example.org/contexts/student-card-v1"
    ],
    "type": [
        "VerifiableCredential",
        "MockCredential"
    ],
    "issuer": "VeryCredible-University",
    "credentialSubject": {
        "name": "Ilya",
        "id": "123456",
        "age": "23",
        "LinkSecret": "",
        "validUntil": "2026-07-16T00:00:00Z",
        "revocationMaterial": "123",
        "metaHash": "f5cae90d60d92d9f69e50f627dd14b3854e1636cd363558ef3e0bd36a8beec60"
    },
    "proof": "ab3523500b272561e22f9abe4b15701f145df396b0ae0b213a32df17d6cc9df98c5eb80b071be467ed119db7161f0ba804c934a16c439f115d234747febe205184e328f3a84d2a00fca8811199cf31791f7ffa24ca3f22647fe0aa762c7a9a348a3d6ddbfc48e337ecf35006d580b1af"
}
==================================================

=== Done ===
```
