# SIH Problem Statement & System Architecture
**Team Solution Proposal | Smart India Hackathon**

---

## 1. Problem Breakdown

### The Context
When confidential documents are shared with a group using broadcast encryption, the file is encrypted once using a random symmetric key. That key is wrapped individually for each recipient's credentials. While this protects data in transit and at rest, every authorized user ultimately decrypts the exact same underlying file.

```
                  ┌─────────────────────────────────────────┐
                  │           Central Distribution          │
                  │   (Single Encrypted File + Wrapped Keys)│
                  └────────────────────┬────────────────────┘
                                       │
            ┌──────────────────────────┼──────────────────────────┐
            ▼                          ▼                          ▼
   ┌─────────────────┐        ┌─────────────────┐        ┌─────────────────┐
   │   User A Decrypt│        │   User B Decrypt│        │   User C Decrypt│
   └────────┬────────┘        └────────┬────────┘        └────────┬────────┘
            │                          │                          │
            ▼                          ▼                          ▼
    Identical Plaintext        Identical Plaintext        Identical Plaintext
   (No unique markers)        (No unique markers)        (No unique markers)
            │                          │                          │
            └──────────────────────────┼──────────────────────────┘
                                       │
                                       ▼
                         ┌───────────────────────────┐
                         │ Leaked File Found Online  │
                         │   Which user leaked it?   │
                         │ (All suspects look equal) │
                         └───────────────────────────┘
```

### Why Standard Solutions Fall Short
* **Server-side logs:** A rogue admin or a compromised root account can wipe or edit access logs. Plus, logs only tell us who *downloaded* a file, not which specific copy ended up on the internet.
* **Static watermarks:** If everyone gets the same watermarked file, we still can't pinpoint the leaker. Generating unique pre-watermarked files for each recipient ahead of time breaks the single-broadcast model and eats up massive storage and bandwidth.

---

## 2. Our Proposed Solution

To solve this, our system enforces four core guarantees:

1. **Forensic Traceability:** The moment a user decrypts a file, a unique, invisible watermark linked to that exact decryption session is embedded into the output.
2. **Non-repudiation:** Decryption requires the user to sign the session request using their private key, proving they initiated it.
3. **Immutable Audit Trail:** All decryption records are pushed to an append-only, tamper-proof ledger managed across multiple independent nodes.
4. **Verifiable Attribution:** If a file leaks, our extraction tool pulls the embedded watermark ID, queries the ledger, and yields cryptographically valid proof of who decrypted that copy.

### Mandatory System Constraints
* **Post-Quantum Cryptography (PQC):** We use NIST-standardized algorithms (ML-KEM for key exchange; ML-DSA/SLH-DSA for digital signatures) to protect against future quantum attacks.
* **Air-Gapped Operation:** The entire stack—PKI, distribution, ledger, and verification engine—runs strictly within an isolated local network without cloud dependencies.

---

## 3. Tech Stack & Implementation Details

| Layer | Selected Tech / Library | Selection Justification |
| :--- | :--- | :--- |
| **PQC Crypto Primitives** | `liboqs` (C/C++) / `OQS-OpenSSL` | Standardized NIST implementations for ML-KEM-768 and ML-DSA-65. |
| **Symmetric Encryption** | AES-256-GCM | Strong authenticated encryption, natively quantum-resistant against Grover's algorithm. |
| **Distributed Ledger** | Hyperledger Fabric (BFT Consensus) | Enterprise-grade permissioned ledger; supports custom chaincode and multi-org validation. |
| **Watermark Engine** | `OpenCV` + Python Custom Modules | Handles multi-layer steganography across text (kerning/line spacing) and images (DCT domain). |

---

## 4. Decryption & Watermarking Workflow

```
[User Request] ──► [ML-KEM Key Decapsulation] ──► [Generate Session & Watermark ID]
                                                              │
                                                              ▼
[Release Document] ◄── [Embed Watermark] ◄── [Ledger Commit Confirmed] ◄── [Sign Record (ML-DSA)]
```

1. **Auth & Decapsulation:** The client application uses the recipient's ML-KEM private key (stored on a hardware token or PKCS#11 software keystore) to decrypt the document key (DEK). The raw plaintext remains strictly in protected volatile memory.
2. **Session Generation:** The app generates a 128-bit random `watermark_id` and constructs a metadata payload:
   $$\text{Payload} = \{\text{cert\_hash}, \text{doc\_id}, \text{timestamp}, \text{watermark\_id}\}$$
3. **Local Signing:** The user's token signs this payload using their ML-DSA private key.
4. **Pre-Release Ledger Commit:** The signed record is sent to the Hyperledger network. **The local client holds the decrypted document in memory and will not render or write it to disk until the transaction is committed by the ledger nodes.**
5. **Dynamic Watermarking:** Once confirmed, the watermarking module embeds the `watermark_id` along with Reed-Solomon error-correction coding directly into the file buffer before displaying it.

---

## 5. Watermarking Techniques

* **Text Documents (PDF / Word):** Subtle micro-adjustments to inter-word spacing, character kerning, and line heights. The watermark is redundantly embedded across multiple paragraphs so partial screenshots or excerpts can still be analyzed.
* **Images & Scans:** Mid-frequency Discrete Cosine Transform (DCT) spread-spectrum embedding. This survives resolution downscaling, lossy JPEG compression, and physical print-and-scan passes.

---

## 6. Threat Analysis & Defensive Safeguards

* **Attempting to bypass the ledger write:**
  * *Defense:* The decryption agent is compiled as a closed binary. The DEK is held in memory and only released to the renderer after receiving a signed block confirmation receipt from the ledger.
* **Collusion Attack (Comparing two distinct copies to strip differences):**
  * *Defense:* Watermark locations are pseudo-randomly permuted using a per-document secret key, making simple diff-based stripping ineffective.
* **Rogue Admin Tampering with Logs:**
  * *Defense:* Ledger consensus requires cross-validation from multiple independent node operators running BFT consensus. No individual admin can modify past blocks.
* **Denial of Decryption ("My key was stolen"):**
  * *Defense:* Decryption operations require physical hardware token access backed by local PIN authentication.

---

## 7. Operational Limitations & Edge Cases

* **The Analog Hole:** If a user captures a clean photo of a high-resolution display, optical distortion can reduce watermark extraction confidence. Error correction helps mitigate this, but severe physical degradation remains a challenge for any steganographic system.
* **Scope of Attribution:** Forensic verification proves beyond a doubt which *user session* generated a given file copy; it cannot prove intent or establish whether the device itself was compromised locally after rendering.
