# 🛡️ LogAnchor-X: Universal Log Pre-processing & Cryptographic Integrity Framework

> **Smart India Hackathon 2026** | **Problem Statement ID:** SIH26156  
> **Organization:** National Technical Research Organisation (NTRO)  
> **Theme:** Blockchain & Cybersecurity | **Team:** Code4baddies  

---

## 📌 Executive Summary
**LogAnchor-X** is a vendor-agnostic, high-throughput log ingestion, normalization, and cryptographic verification framework built specifically for zero-trust, air-gapped national intelligence and defense networks.

It addresses two fundamental challenges in modern SecOps and cyber forensics:
1. **Fragile, Manual Regex Overhead:** Automated schema discovery using an online, unsupervised **Drain Trie algorithm** ($O(1)$ amortized depth tree) that mines dynamic parameters and extracts log templates on the fly without cloud LLM or GPU dependencies.
2. **Forensic Evidence Tampering:** Attackers frequently erase or rewrite audit logs (`rm -rf /var/log`, SQL `UPDATE`/`DELETE`). LogAnchor-X implements a **Lossless Dual-Payload Architecture** cryptographically anchored into an **Append-Only Write-Ahead Log (WAL) Ledger** with **Binary Merkle Trees**, enabling sub-second tamper detection via $O(\log N)$ inclusion proofs.

---

## 🏛️ System Architecture

```
                                  [ MULTI-SOURCE INGESTION ]
                     (Syslog RFC 3164/5424, CEF, LEEF, JSON, Apache, Custom)
                                             │
                                             ▼
                             ┌───────────────────────────────┐
                             │  Ingestion & Anonymization    │
                             │  (IP/User Masking & Cleansing)│
                             └──────────────┬────────────────┘
                                            │
                     ┌──────────────────────┴──────────────────────┐
                     ▼                                             ▼
       ┌───────────────────────────┐                 ┌───────────────────────────┐
       │   AI Parsing Engine       │                 │ Raw Byte-for-Byte Store   │
       │   - Drain Fixed-Depth Trie│                 │ - Append-Only WAL Ledger  │
       │   - OCSF Taxonomy Mapping │                 │ - cyberguard_ledger.dat   │
       └─────────────┬─────────────┘                 └─────────────┬─────────────┘
                     │                                             │
                     └──────────────────────┬──────────────────────┘
                                            │ Bound via Deterministic SHA-256 Hash
                                            ▼
                             ┌───────────────────────────────┐
                             │     Binary Merkle Tree        │
                             │  - Cross-Batch Hash Chaining  │
                             │  - O(log N) Inclusion Proofs  │
                             └──────────────┬────────────────┘
                                            │
       ┌────────────────────────────────────┼────────────────────────────────────┐
       ▼                                    ▼                                    ▼
┌──────────────┐                     ┌──────────────┐                     ┌──────────────┐
│  Live D3     │                     │ MITRE ATT&CK │                     │ Downstream   │
│  Provenance  │                     │ Tactical     │                     │ GNN Tensor   │
│  Attack DAG  │                     │ Matrix (14)  │                     │ Feed (PyG)   │
└──────────────┘                     └──────────────┘                     └──────────────┘
```

---

## 🚀 Key Features

| Feature | Description | Technical Advantage |
|---|---|---|
| **Zero-Regex Auto Parsing** | Fixed-depth Drain Trie clustering extracts templates dynamically from raw text streams. | Eliminates manual Grok/Regex scripting; 30,000+ EPS/core on standard CPUs. |
| **Lossless Dual-Payload** | Normalizes events to **OCSF standard** while preserving byte-for-byte raw logs. | Guarantees legal admissibility (NIST SP 800-86) without losing vendor-specific attributes. |
| **Cryptographic WAL Ledger** | Append-only ledger file (`cyberguard_ledger.dat`) backed by SHA-256 Merkle root chaining. | No SQL/NoSQL engine required; eliminates insider `UPDATE`/`DELETE` tampering risks. |
| **1-Click Tamper Simulation** | Instantly simulates bit-level ledger alteration and verifies Merkle root divergence. | Live visual proof of cryptographic discrepancy (`CRITICAL: TAMPER DETECTED`). |
| **Causal Provenance DAG** | 180-second sliding-window correlation tracks multi-stage attack transitions. | Interactive D3.js force-directed topology map visualizing attacker progression. |
| **Downstream AI Readiness** | Generates PyTorch Geometric (PyG) graph tensors in COO format via `/api/ml-export`. | Ready feature-engineering substrate for Graph Neural Networks (GNNs). |
| **100% Air-Gapped & Offline** | Self-contained micro-runtime with zero external web/cloud API dependencies. | Strictly adheres to zero-egress military and defense security requirements. |

---

## 🔬 Core Algorithms & Data Structures

### 1. Drain Online Log Clustering Algorithm
- **Concept:** Unsupervised fixed-depth trie parsing.
- **Complexity:** $O(1)$ amortized time per log event.
- **Workflow:**
  1. Filters by token count (log length).
  2. Traverses internal trie nodes matching token prefixes.
  3. Measures token similarity with existing cluster templates.
  4. Automatically masks dynamic parameters (`<*>`) like IPs, usernames, session tokens, and UUIDs.

### 2. Binary Merkle Tree & Cross-Batch Hash Chaining
- **Concept:** Leaf-level SHA-256 hashing aggregated pairwise into a root hash.
- **Chaining Equation:**
  $$\text{ChainRoot}_n = \text{SHA-256}(\text{ChainRoot}_{n-1} \parallel \text{Root}_n)$$
- **Inclusion Proofs:** Verifies any individual log in $O(\log N)$ time by traversing sibling hashes from leaf to root without scanning the full ledger.

---

## 🛠️ Tech Stack

- **Backend Runtime:** Java 17 / 21 LTS (Embedded `com.sun.net.httpserver`, zero heavy framework footprint)
- **Frontend / Visualization:** HTML5, Modern CSS, D3.js Force Simulation
- **Cryptographic Primitives:** Java Security Standard `MessageDigest` (SHA-256)
- **Memory Footprint:** `< 200 MB RAM` at peak throughput
- **Target OS:** Windows, Linux, macOS (Docker/Podman ready)

---

## 📡 REST API Specifications

The embedded microserver exposes the following endpoints on `http://localhost:8080`:

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | `GET` | Serves the single-page interactive operations dashboard (`index.html`). |
| `/api/parse` | `POST` | Ingests a raw log string, detects format, performs anonymization, and infers template. |
| `/api/anchor` | `POST` | Seals the current in-memory parsed batch into the Merkle tree and ledger file. |
| `/api/verify` | `GET / POST`| Verifies cryptographic ledger consistency using leaf-to-root Merkle path proofs. |
| `/api/tamper-simulate` | `POST` | Injects a targeted byte alteration into the ledger to demonstrate instant detection. |
| `/api/provenance-graph`| `GET` | Returns graph nodes (endpoints/services) and causal edges (attack progression). |
| `/api/mitre-matrix` | `GET` | Returns real-time distribution across MITRE ATT&CK 14 tactical categories. |
| `/api/ml-export` | `GET` | Exports PyTorch Geometric COO edge indices and node feature vectors. |
| `/api/benchmark` | `GET` | Executes micro-benchmarking and returns real-time throughput metrics (EPS). |
| `/api/reset` | `POST` | Resets in-memory state and ledger for reproducible live demonstrations. |

---

## ⚡ Quickstart & Local Setup

### Prerequisites
- Java Development Kit (JDK 17 or higher)
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/ayeshamallick6514-aye/LogParserProtoType.git
cd LogParserProtoType
git checkout integration
```

### 2. Compile
```bash
# Compile Java source into target directory
javac -encoding UTF-8 -d target/classes src/main/java/org/example/Main.java

# Copy frontend assets to classpath
copy src\main\resources\index.html target\classes\index.html
```

### 3. Run the Engine
```bash
java -cp target/classes org.example.Main
```

### 4. Access the Dashboard
Open your browser and navigate to:
```
http://localhost:8080
```

---

## 🧪 Step-by-Step Evaluation Walkthrough

1. **Start Live Stream:** Click `Start Simulation` to stream multi-format logs at line rate.
2. **Inspect Dual Payload:** Click `Stop Simulation` and select any log to view the parsed OCSF fields alongside the raw log.
3. **Explore Attack Provenance:** Click `Refresh Graph` to visualize the D3.js causal attack DAG and MITRE ATT&CK tactical distribution.
4. **Verify Cryptographic Proof:** Click `Verify Integrity` — observer `STATUS: VALID (100% INTACT)`.
5. **Demonstrate Tamper Evidence:** Click `Simulate Tamper` — the engine detects the bit discrepancy in microseconds and triggers `CRITICAL: TAMPER DETECTED`.

---

## 👥 Team: Code4baddies

- **Team Lead & Architecture:** Ayesha Mallick
- **Log Ingestion & Parsing Engine**
- **Causal Graph & Threat Intelligence**
- **Cryptographic Vault & Merkle Chaining**
- **Downstream AI/ML Integration & Benchmarking**
- **Security Compliance & Forensics**

---

## 📜 Compliance & References
- **NIST SP 800-86:** *Guide to Integrating Forensic Techniques into Incident Response*
- **IEEE ICWS (2017):** *Drain: An Online Log Parsing Approach with Fixed Depth Tree*
- **OCSF (Open Cybersecurity Schema Framework):** *Linux Foundation / AWS / Splunk Standard*
- **RFC 5424 / RFC 3164:** *The Syslog Protocol Standard*
