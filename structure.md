### 1. Introduction

* 1.1 Problem: trusted-node assumption breaks at scale
* 1.2 Approach: remotely attested key relay (SGX-QKMS)
* 1.3 Contributions and limitations (prototype maturity, what’s out-of-scope)

### 2. Background and related work

* 2.1 QKD networks: distance limits, trusted relays, hop-by-hop OTP
* 2.2 ETSI GS QKD 014 and the missing inter-KME plane
* 2.3 Partially trusted relaying: multipath XOR / secret sharing + hybrid PQC
* 2.4 TEEs and remote attestation (SGX, DCAP, RATS models)
* 2.5 Attested secure channels: RA-TLS / RATLS / HTTPA

### 3. SGX-QKMS Design

* 3.1 System model and goals (entities, assets, adversary, security objectives)
* 3.2 Inter-KME HTTPS relay protocol (endpoints, message formats, replay protection, errors)
* 3.3 Enclave identity and policy (MRENCLAVE/MRSIGNER allowlist, version pinning, debug gating)
* 3.4 CSR + certificate provisioning (keypair in enclave, attestation-bound CSR, CA issuance)
* 3.5 Attested channel binding (where HTTPA fits vs attested TLS; what you actually verify)
* 3.6 Configuration integrity (embedding CA + graph into MRENCLAVE vs signed/served manifests)
* 3.7 Progressive rollout (compatibility modes, bounded window, mixed SGX/non-SGX routing)

### 4. Experimental evaluation

* 4.1 Setup (hardware SGX, DCAP/PCCS, software stack, measurement methodology)
* 4.2 Topologies and workloads (SECOQC-style graph; subset SGX-enabled; relay patterns)
* 4.3 Metrics (attestation latency, per-hop latency, end-to-end setup time, throughput, CPU/EPC impact)
* 4.4 Rollout experiments (legacy-only vs SGX-only vs hybrid; failure/collateral refresh behavior)

### 5. Security analysis and discussion

* 5.1 What is protected (keys, relay logic, channel endpoints) and under what assumptions
* 5.2 Attack surface (malicious OS/admin, network attacker, rollback, DoS, side channels)
* 5.3 Residual risks + mitigations (sealing/rollback limits, version policy, hardening roadmap)
* 5.4 Comparison (TPM/IMA boot attestation vs SGX; why SGX is needed for your goal)

### 6. Conclusion

* 6.1 Summary of results
* 6.2 Future work (standardization, broader TEE support, stronger policy distribution, side-channel defenses)
