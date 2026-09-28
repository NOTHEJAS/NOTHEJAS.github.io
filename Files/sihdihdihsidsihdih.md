# SIH PROBLEM STATEMENT RESEARCH AND ARCHI


A: The problem in detail

The scenario

Sensitive documents are often shared with a group under a broadcast-encrypt, individually-decrypt model:

The sender encrypts the document once with a random symmetric key.
That key is wrapped separately for each authorized recipient.
Each recipient unwraps the key with their own credentials and decrypts.

Encryption protects the file in transit and at rest, but after decryption every recipient holds the same plaintext bytes.

Why attribution fails

If a document goes to one person and leaks, you know who did it. If it goes to 40 people and leaks, all 40 are equally plausible suspects. The leaked file carries no trace of which decryption produced it, so the "anonymity set" is the whole group. Innocent people are suspected, the guilty one can hide, and an investigation can't reach a defensible conclusion.

Why the usual defenses don't work
Existing safeguard	Why it fails
Server-side access logs	A privileged administrator can edit or delete them, so a leaker with an insider friend, or a compromised admin account, can erase the evidence. They also record that someone accessed a file, not which copy leaked.
Static watermark before distribution	If every recipient gets the same watermark, the leaked copy still points to the whole group. Giving each recipient a different pre-distribution copy breaks the "encrypt once" model and doesn't say which decryption session leaked.
What the challenge asks for

The system has to satisfy four properties at once:

Forensic distinctness. Each decrypted copy looks identical to a human but carries a unique hidden mark tied to that recipient's decryption session, created at the moment of decryption.
Non-repudiation. The decryption event is signed with the recipient's own private key, so they can't claim someone else did it.
Immutability. The signed record goes into a tamper-evident ledger that no single administrator can rewrite, so no one can retroactively hide or forge it.
Verifiable attribution. From a leaked copy you can extract the mark, look it up in the ledger, verify the signature and ledger integrity, and produce evidence that a third party can check independently.
Two further constraints
Post-quantum cryptography. Use NIST-standardized algorithms: ML-KEM (FIPS 203) for key exchange and ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures. Evidence must hold up for decades, and classical signatures could be forged by future quantum computers.
Air-gapped operation. There is no cloud KMS, no public blockchain, and no internet. PKI, ledger, watermarking, and verification must all run inside an isolated network.
Hard parts hidden in the requirements
Trust at the decryption point. Watermarking happens where the plaintext appears, which is on the recipient's side. The system has to make sure plaintext can't be released without the signed record and the unique watermark.
Robustness. A leak may be a screenshot, a printout that was scanned, a format conversion, or a partial excerpt. The watermark has to survive these.
Collusion. Two recipients could compare copies and average or diff away the mark.
False accusation. The evidence must be strong enough to hold up against "someone stole my key."
Ordering. The ledger commit must happen before the document is shown, or a recipient could decrypt and then block the commit.
Part 2: System architecture
High-level view
                    ┌──────────────────────────────────────────────┐
                    │        AIR-GAPPED SECURE ENCLAVE NETWORK     │
                    │                                              │
 ┌───────────────┐  │  ┌──────────────────┐                        │
 │ Offline Root  │──┼─▶│ Identity & PKI   │  issues PQ certs       │
 │ CA (ML-DSA /  │  │  │ Service          │  (ML-KEM + ML-DSA)     │
 │ SLH-DSA, HSM) │  │  └────────┬─────────┘                        │
 └───────────────┘  │           │ enrolment                        │
                    │           ▼                                  │
 ┌───────────────┐  │  ┌──────────────────┐   ┌─────────────────┐  │
 │ Sender Client │──┼─▶│ Encryption /     │──▶│ Permissioned    │  │
 │               │  │  │ Distribution Svc │   │ DLT (BFT        │  │
 └───────────────┘  │  └────────┬─────────┘   │ validators)     │  │
                    │           │ package     │ ┌────┐ ┌────┐   │  │
                    │           ▼             │ │ V1 │ │ V2 │…  │  │
 ┌───────────────┐  │  ┌──────────────────┐   │ └────┘ └────┘   │  │
 │ Recipient     │◀─┼──│ Secure Decrypt   │◀─▶│ Ledger API +    │  │
 │ (smartcard/   │  │  │ Agent            │   │ Smart contracts │  │
 │  token)       │  │  │ • decapsulate    │   └────────┬────────┘  │
 └───────────────┘  │  │ • sign record    │            │           │
                    │  │ • embed watermark│            │           │
                    │  └──────────────────┘            │           │
                    │                                  ▼           │
 ┌───────────────┐  │  ┌──────────────────┐   ┌─────────────────┐  │
 │ Investigator  │──┼─▶│ Forensic Verifier│──▶│ Signed Evidence │  │
 │ (leaked file) │  │  │ • extract WM     │   │ Report          │  │
 └───────────────┘  │  │ • ledger lookup  │   └─────────────────┘  │
                    │  │ • verify sigs    │                        │
                    │  └──────────────────┘                        │
                    └──────────────────────────────────────────────┘
Component by component
1. Identity and PKI (offline)
An offline root CA signs an intermediate CA. Use SLH-DSA (hash-based, conservative security assumptions) or ML-DSA-87 for these long-lived keys.
Each recipient is enrolled with two key pairs: an ML-KEM-768/1024 pair for receiving keys and an ML-DSA-65 pair for signing. Private keys live on a hardware token or smartcard/HSM that supports PQC, or in a PQ-capable software keystore for a prototype.
Certificates bind the key to the identity (name, clearance, validity period). A certificate revocation list is distributed inside the enclave.
Authentication at decryption combines the token, a PIN, and optionally biometrics.
2. Encryption and distribution service

This is a KEM-DEM (hybrid) scheme:

Generate a random document key (DEK) and encrypt the file with AES-256-GCM.
For each authorized recipient, run ML-KEM encapsulation against their public key to get a shared secret, then use that secret (via HKDF) to wrap the DEK.
Produce a package containing the ciphertext, the per-recipient wrapped keys, a manifest, and the sender's ML-DSA signature.
Register the document on the ledger with its doc_id, content hash, sender, and authorized recipient list.

AES-256 is quantum-resistant against Grover's algorithm, so symmetric encryption is fine to keep.

3. Secure decrypt agent (the core component)

The order of operations matters:

Recipient authenticates and the agent decapsulates the wrapped DEK, so the plaintext exists only in protected memory.
The agent creates a decryption session: a random session_id and a random, opaque watermark_id (say 128 bits).
It builds a decryption record: {recipient_cert_fingerprint, doc_id, doc_hash, timestamp, session_id, watermark_id, nonce}.
The recipient signs the record with their ML-DSA key (on the token).
The signed record is submitted to the ledger, and the agent waits for a commit receipt (consensus finality).
Only then does the watermark engine embed the mark and release or render the document.

Committing before release means no signed and committed record means no readable document, so a recipient can't decrypt "off the books."

Watermark engine. The payload is the watermark_id plus error-correcting code (Reed-Solomon, BCH, or LDPC). The watermark_id is deliberately opaque, so a leaked file doesn't reveal identity on its own and the ledger lookup is required. Embedding is layered by document type:

Text and Word or PDF documents. Micro-variations in glyph spacing or kerning, line-spacing perturbations, and optionally zero-width characters. Encode the ID redundantly across many pages or paragraphs so excerpts still contain it.
Images and scanned pages. Spread-spectrum embedding in the DCT or wavelet domain, which survives compression, resizing, and print-and-scan to a degree.
Multiple layers. Combining layers means one stripping technique doesn't remove everything.

A per-document watermark secret key seeds the embedding pattern, so attackers can't easily locate and strip the mark.

Where this runs. There are two options with different trust tradeoffs:

Client-side agent, hardened and preferably attested via a TEE or secure boot. It is simple, but the endpoint is not fully trusted.
On-premise decryption gateway in the enclave, where the recipient views through a controlled channel. The gateway is more trustworthy, but access is more constrained.

For a prototype, build the client-side agent and describe the gateway as the hardened deployment option.

4. Permissioned DLT (the immutable audit layer)
Use a permissioned blockchain with BFT consensus (for example Hyperledger Fabric with a BFT ordering service, Besu with QBFT, or a custom PBFT/Tendermint-style chain). No public network is involved.
Validator nodes are operated by different organizations or departments, so no single administrator can rewrite history. Changing a past block requires collusion above the fault threshold (roughly ⅓ or more of validators).
Blocks are hash-chained and contain Merkle trees of transactions. Validators sign blocks with ML-DSA, so the chain's integrity is itself post-quantum.
Smart contracts (chaincode) enforce these rules on submission:
The signature verifies against a valid, unexpired, non-revoked certificate.
The recipient is on the document's authorized list.
The watermark_id is unique.
The record is append-only, with no update or delete operations.
On-chain data: recipient certificate fingerprint (pseudonymous), doc_id, event type, timestamp, watermark_id, signature, and the record hash. Never put document content on the ledger.
Time: without NTP from the internet, use an internal trusted time source plus a consensus-agreed block timestamp.
Extra tamper evidence: periodically export the signed chain-head hash (Merkle root) to WORM media or print it and store it in a separate secure location, so even a full-network compromise can be detected.
5. Forensic verification service

Given a leaked document:

Extract the watermark with the extractor. It handles degradation, applies ECC decoding, and reports a confidence score.
Look up the watermark_id in the ledger index.
Verify the signature: validate the ML-DSA signature over the record using the recipient's certificate, and check the certificate chain to the offline root and its validity at that time.
Verify ledger integrity: check the Merkle inclusion proof, the block hash chain, and the validator signatures on the block.
Cross-check the leaked document's content against the registered doc_hash (allowing for watermark differences).
Generate a signed evidence report containing the recipient, session, document, timestamp, signature, proofs, and confidence. It is self-contained so an independent party can re-verify it offline.
Mapping to the 10-step workflow
Workflow step	Component
1. Sender encrypts and distributes	Encryption service (AES-GCM + ML-KEM wrapping)
2. Recipient decrypts	Secure decrypt agent + token authentication
3. Unique watermark generated	Watermark engine (random opaque ID + ECC)
4. Recipient signs the record	ML-DSA signature on the token
5. Committed to ledger	Permissioned BFT DLT with validating chaincode
6. Fingerprinted copy delivered	Released only after ledger commit
7. Extract watermark from leak	Forensic extractor
8. Match against ledger	Ledger index lookup by watermark_id
9. Verify signature and ledger	ML-DSA verify + Merkle/chain/validator checks
10. Verifiable record produced	Signed evidence report
Threat model and mitigations
Threat	Mitigation
Admin tries to erase or alter records	BFT multi-organization validators; append-only chaincode; external anchoring of chain heads
Recipient denies decrypting	Signature made with their own token-held key; certificate binding
Recipient claims key theft	Hardware token plus PIN or biometric; revocation records; timestamped ledger evidence
Recipient strips or degrades the watermark	Redundant, multi-layer embedding; ECC; secret-keyed pattern
Collusion (comparing copies)	Randomized, keyed embedding positions; collusion-resistant coding (e.g., Tardos-style codes) as an extension
Decrypt without committing	Commit-before-release; DEK only usable inside the agent
False accusation via forged watermark	Watermark ID is random and only meaningful with a matching signed ledger record
Quantum attacker later forges signatures	ML-DSA / SLH-DSA throughout; ML-KEM for key exchange
Ledger data leaks metadata	Pseudonymous IDs; no content on-chain; permissioned access
Honest limitations

These are worth stating to judges:

The analog hole: someone can photograph a screen or retype a document. Watermarks reduce but don't eliminate this risk, and heavy degradation lowers extraction confidence.
The endpoint is the weak point unless you use a TEE or a controlled gateway.
Attribution establishes whose session produced the copy, and the signed record ties that to their key. It doesn't prove intent, and the report should say so.
