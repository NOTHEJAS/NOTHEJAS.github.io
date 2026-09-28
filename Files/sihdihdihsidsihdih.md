# ok so heres the whole crypto attribution thing explained

ngl this problem sounds mad complicated but its actually kinda simple once u get it. 

---

## PART 1: whats the actual problem here 


so basically when u send a sensitive doc to a GROUP of ppl, it works like this:

- sender encrypts the file ONE time w a random key
- that key gets wrapped up seperately for each person whos allowed to see it
- each person unlocks THEIR version of the key w their own login/creds and decrypts

 encryption protects the file while its traveling and sitting there. but heres the catch — once its decrypted, EVERYONE has the exact same plain readable file.

### why attribution (aka figuring out who leaked it) straight up fails

if u send a file to ONE person and it leaks... duh, u know who did it, easy sliming him.

but if u send it to like 40 ppl and it leaks?? now all 40 of them are equally suspicious . the leaked file doesnt have ANY clue baked into it about who opened it. so everyone's a suspect, the actual leaker gets to hide in the crowd, and ur investigation just kinda... dies. no reciepts, no justice.

### why the stuff ppl normally do doesnt fix it

| the "fix" | why it flops |
|---|---|
| **server logs** | an admin w too much power can just edit or delete these. if the leaker has an insider buddy (or the admin account gets hacked), the evidence is just. gone. also logs only say "someone opened it" not "THIS exact copy is the one that leaked" |
| **watermark before sending it out** | if everyone gets the SAME watermark ur back to square one, whole group is sus again. and if u give everyone a different copy BEFORE distributing, that breaks the whole "encrypt once" thing n still doesnt tell u which decrypt SESSION leaked |

### what this challenge actually wants us to build


1. **forensically different copies** — every decrypted file LOOKS the same to a human eye but has a hidden unique mark tied to that specific person's decrypt session, made the second they decrypt it
2. **no take backs (non-repudiation)** — the decrypt event gets signed w the recipients OWN private key so they literally cant say "wasnt me" later
3. **cant be erased (immutability)** — the signed record goes onto a tamper proof ledger that no single admin can rewrite, so no1 can secretly cover their tracks
4. **can actually verify who did it** — from a leaked copy u gotta be able to pull the watermark, check it against the ledger, verify the sig n the ledger integrity, and spit out actual proof a third party can double check

### 2 more constraints bc why not make it harder

- **post-quantum crypto** — gotta use NIST approved algos: ML-KEM (FIPS 203) for key exchange n ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures. reasoning: this evidence needs to hold up for DECADES and regular signatures could get cracked by quantum computers down the line
- **air gapped / fully offline** — no cloud KMS, no public blockchain, no internet AT ALL. identity stuff, the ledger, watermarking, verification, all of it has to run inside a sealed off network. its giving military vibes (bc it literally is the MoD lol)

### the sneaky hard parts hiding in the requirements 

- **trust at the moment of decryption** — the watermark gets slapped on wherever the plaintext shows up, which is on the RECIPIENTS side. gotta make sure they cant just grab the plaintext without the signed record n watermark happening first
- **surviving damage** — a leak could be a screenshot, a printed n rescanned page, a format convert, or just a lil snippet. watermark needs to survive all that chaos
- **collusion** — 2 sus recipients could compare their copies side by side n try to diff/average out the watermark
- **false accusations** — evidence gotta be strong enough to survive someone crying "my key got stolen!!"
- **timing/ordering** — the ledger commit HAS to happen before the doc even shows up on screen, otherwise a recipient could decrypt then just block the commit from happening lol sneaky

---

## PART 2: the actual system architecture (C lauda - claude did this shit i am still figuring it out)

### big picture view

```
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
```



### breaking down each piece

#### 1. identity + PKI (fully offline bc we gatekeeping )

- **offline root CA** signs an intermediate CA. use SLH-DSA (hash based, super paranoid-safe assumptions) or ML-DSA-87 for these keys that live forever
- every recipient gets enrolled w **2 keypairs**: a ML-KEM-768/1024 pair for recieving keys n a ML-DSA-65 pair for signing stuff. private keys live on a **hardware token/smartcard/HSM** that supports PQC (or a software keystore if this is just a prototype, we not tryna break the bank)
- certificates tie the key to an actual identity (name, clearance lvl, expiry date). theres also a revocation list floating around inside the enclave for keys that got yeeted
- auth at decrypt time = token + PIN + maybe biometrics for extra flex

#### 2. encryption + distribution service

this is a hybrid KEM-DEM setup, breakdown:

1. make a random document key (DEK), encrypt the file w **AES-256-GCM**
2. for EACH recipient, run **ML-KEM encapsulation** against their public key, get a shared secret, use that (thru HKDF) to wrap up the DEK just for them
3. package it all up: ciphertext + per-recipient wrapped keys + manifest + senders ML-DSA signature
4. register the doc on the ledger w its doc_id, content hash, sender, n who's allowed to see it

AES-256 is already quantum resistant against Grover's algo so we chillin on the symmetric side, no need to overthink that part

#### 3. secure decrypt agent (this is like. the MAIN thing)

order matters a LOT here apparently

1. recipient logs in, agent **decapsulates** the wrapped DEK — plaintext only exists in protected memory, nowhere else
2. agent spins up a **decryption session**: random session_id + random opaque watermark_id (128 bits, basically unguessable)
3. builds a **decryption record**: recipient cert fingerprint, doc_id, doc_hash, timestamp, session_id, watermark_id, nonce — all bundled up
4. recipient **signs this record** w their ML-DSA key (living on the hardware token)
5. signed record gets **sent to the ledger**, agent waits for it to actually get confirmed (consensus finality, not just "sent")
6. **ONLY after that** does the watermark engine actually embed the mark n let the doc render/open

the whole "commit before u can even see the file" thing means theres literally no way to decrypt off the books. no commit = no readable doc, straight up

**watermark engine deets.** the payload is just the watermark_id + error correction code (reed-solomon, BCH, or LDPC so it survives damage). watermark_id is intentionally meaningless on its own — a leaked file doesnt reveal WHO by itself, u gotta cross ref the ledger. embedding depends on file type:

- **text/word/pdf docs** — tiny tweaks to glyph spacing/kerning, subtle line-spacing changes, maybe zero-width characters hidden in there. repeat the id across tons of pages/paragraphs so even a small excerpt still has it
- **images/scans** — spread-spectrum embedding in the DCT/wavelet domain, this survives compression, resizing, even print-then-rescan reasonably well
- **layering it up** — stack multiple embedding methods so one removal trick cant strip everything at once

each doc also gets its own watermark secret key that seeds the embedding pattern so randoms cant just find n scrub the mark easy

**where does this actually run tho.** 2 options w different trust levels:

- **client side agent**, hardened, ideally w a TEE or secure boot backing it up. simple to build but the endpoint itself isnt 100% trusted
- **on-prem decryption gateway** inside the enclave, recipient views the doc thru a locked down channel. way more trustworthy but access is more restrictive

for a prototype just build the client agent n mention the gateway as the "for real deployment" upgrade option

#### 4. permissioned DLT 
- use a **permissioned blockchain** w BFT consensus (hyperledger fabric w BFT ordering, besu w QBFT, or roll ur own PBFT/tendermint-ish chain). 
- **validator nodes run by different orgs/departments** so no single admin can rewrite history. to change past blocks u'd need collusion above the fault threshold (~1/3+ of validators), basically not happening
- blocks are **hash chained** w merkle trees of transactions inside. validators sign blocks w ML-DSA so even the chains integrity is quantum proof
- **smart contracts (chaincode)** enforce rules when stuff gets submitted:
  - sig has to verify against a valid, unexpired, non-revoked cert
  - recipient actually has to be on that docs allowed list
  - watermark_id has to be unique, no dupes
  - records are append-only, straight up NO updating or deleting allowed
- **on-chain data**: recipient cert fingerprint (pseudonymous so not fully exposed), doc_id, event type, timestamp, watermark_id, signature, record hash. NEVER put actual document content on chain, thats a nono
- **timing** — no internet = no NTP, so use an internal trusted time source + consensus-agreed block timestamps
- **extra paranoia layer** — periodically export the signed chain-head hash (merkle root) to WORM media, or even print it n lock it in a safe somewhere else. so even if the WHOLE network got popped somehow, u could still catch it

#### 5. forensic verification service

given a leaked doc, heres the flow:

1. **extract** the watermark using the extractor tool. it handles degraded/damaged files, does ECC decoding, spits out a confidence score
2. **look up** the watermark_id in the ledger index
3. **verify the signature** — check the ML-DSA sig on the record against the recipients cert, n make sure the cert chain traces back to the offline root n was valid AT THAT TIME
4. **verify ledger integrity** — check the merkle inclusion proof, the block hash chain, n the validator signatures on that block
5. **cross check** the leaked docs content against the registered doc_hash (accounting for the watermark being different obviously)
6. **generate a signed evidence report** with everything: recipient, session, doc, timestamp, sig, proofs, confidence score. its self contained so anyone else can re-verify it offline too, no trust required

### mapping back to the 10 step workflow (for reference)

| workflow step | which component handles it |
|---|---|
| 1. sender encrypts n distributes | encryption service (AES-GCM + ML-KEM wrapping) |
| 2. recipient decrypts | secure decrypt agent + token login |
| 3. unique watermark made | watermark engine (random opaque id + ECC) |
| 4. recipient signs the record | ML-DSA sig on the token |
| 5. commited to ledger | permissioned BFT DLT w validating chaincode |
| 6. fingerprinted copy delivered | only released after ledger commit confirms |
| 7. extract watermark from leak | forensic extractor |
| 8. match against ledger | ledger index lookup by watermark_id |
| 9. verify sig n ledger | ML-DSA verify + merkle/chain/validator checks |
| 10. verifiable record produced | signed evidence report |

### threat model (aka who's tryna mess this up n how we stop em)

| threat | how we shut it down |
|---|---|
| admin tries to erase/edit records | BFT multi-org validators, append-only chaincode, external chain-head anchoring |
| recipient denies decrypting | sig made w THEIR OWN token key, cert binding proves it was them |
| recipient claims "my key got stolen!!" | hardware token + PIN/biometric, revocation records, timestamped evidence |
| recipient tries to strip the watermark | redundant multi-layer embedding, ECC, secret-keyed pattern |
| collusion (comparing copies side by side) | randomized keyed embedding positions, collusion-resistant coding (tardos codes) as a bonus extension |
| decrypt without commiting the record | commit-before-release rule, DEK only usable INSIDE the agent |
| fake watermark = false accusation | watermark id is random n meaningless w/o a matching signed ledger record |
| quantum computer forges sigs later | ML-DSA/SLH-DSA everywhere, ML-KEM for key exchange |
| ledger leaking metadata | pseudonymous ids, zero content on chain, permissioned access only |

###  the limitations (dont oversell this to judges)

- **the analog hole is still a thing** — someone COULD just photograph their screen or retype the doc by hand. watermarks help a lot but dont fully solve this, n heavy damage lowers how confident the extraction is
- the endpoint (recipients device) is still the weakest link unless u got a TEE or locked down gateway
- this proves WHOSE session produced the leaked copy n ties it to their key — it does NOT prove intent, the report should be honest about that

### CLAUDE SIR KA suggested stack if ur actually building this for the hackathon

- **PQC**: liboqs or openSSL 3.5+ (ML-KEM, ML-DSA, SLH-DSA)
- **symmetric**: AES-256-GCM, HKDF
- **watermarking**: python w opencv/numpy (DCT/DWT for images), PDF glyph spacing tricks, reed-solomon (`reedsolo` lib)
- **ledger**: hyperledger fabric OR just build a lil custom PBFT/hash-chain network w 4 validators in docker on an isolated network
- **verifier**: CLI or a basic web UI that spits out the signed evidence bundle
- **demo idea**: 3 recipients decrypt the same file, then u "leak" one copy on purpose, degrade it a bit (screenshot it, compress it whatever), n the system correctly IDs the exact recipient n session. thats ur money shot for the demo

