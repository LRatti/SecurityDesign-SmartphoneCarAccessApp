# Security Design for a Smartphone Car Access App

> A comprehensive security architecture and proof-of-concept for a smartphone-based car access system, developed for the Information Security course at Ghent University.

This project addresses the challenge of replacing traditional RFID/NFC smart cards with a secure smartphone application for vehicle access. The goal was to design a robust, end-to-end security system that not only provides convenience but also enhances security through modern cryptographic protocols and a multi-layered defense strategy.

## ✨ Key Features

-   **Secure Vehicle Control:** Remotely lock, unlock, and start the car.
-   **Multi-Factor Authentication (MFA):** A risk-based authentication system combining biometrics (Face ID/Fingerprint) and a fallback PIN for secure user access.
-   **Secure Access Sharing:** A digital delegation mechanism allows car owners to grant temporary and revocable access to other users without physically transferring a key.
-   **Remote Access Revocation:** Owners can instantly revoke access for any user or device, which is critical in case of a lost/stolen phone or a suspended driver's license.
-   **End-to-End Encrypted Communication:** All communications between the smartphone, car, and backend server are secured using **Mutual TLS (mTLS) 1.3**.
-   **Robust Key Management:** A Public Key Infrastructure (PKI) manages identities. Cryptographic keys are generated and stored securely within hardware-backed environments like a **Trusted Execution Environment (TEE)** or Secure Enclave.
-   **Comprehensive Threat Modeling:** The design includes countermeasures against a wide range of attacks, including Man-in-the-Middle (MITM), Replay, Malware, and Physical Device Theft.

## 🏛️ System Architecture

The system is composed of three main components that communicate securely:

1.  **Smartphone App (Client):** The user's interface for managing the vehicle. It securely stores the user's private keys and certificates and is responsible for initiating commands.
2.  **Backend Server:** Acts as the Certificate Authority (CA) and trust anchor. It manages user identities, validates certificates, handles access delegation logic, and syncs driver's license statuses.
3.  **Vehicle's Onboard System (ECU):** The car's embedded system, equipped with a secure hardware module (e.g., HSM/TPM) to store its own cryptographic keys. It is responsible for executing commands after successful authentication.

### Communication Flow

The core of the security relies on a **mutual authentication** process where the app and the car verify each other's identity using digital certificates signed by the trusted backend server. Session keys are established using the **Elliptic Curve Diffie-Hellman (ECDH)** protocol to ensure Perfect Forward Secrecy.

## 🛡️ Security Mechanisms Deep Dive

This project goes beyond just relying on TLS and implements several application-level security protections.

| Feature / Threat | Mitigation Strategy |
| :--- | :--- |
| **Unauthorized Access** | Multi-Factor Authentication (Biometrics + PIN). |
| **Eavesdropping / MITM** | Mutual TLS 1.3 with certificate pinning. |
| **Replay Attacks** | Signed timestamps and strictly increasing sequence numbers (nonces) in every command. |
| **Device Theft** | Keys are stored in the TEE/Secure Enclave, protected by biometrics. Remote revocation via a web portal is available. |
| **Malware / Rooting** | The design recommends runtime integrity checks, root detection, and code obfuscation. |
| **Access Sharing Abuse** | Digitally signed, short-lived delegation tokens with granular permissions. All activity is logged. |

## 💻 Proof of Concept (PoC)

A proof-of-concept application was developed in Python to simulate the security mechanisms and demonstrate their effectiveness.

### Prerequisites

-   Python 3.8+
-   pip (Python package installer)

### Installation & Running

1.  **Clone the repository:**
    ```sh
    cd your-repository-name
    git clone 
    
    ```

2.  **Install the required dependencies.** For more information refer to the "how_to_test.md" file in the README directory.

3.  **Run the simulation** as described by the "how_to_test.md" file in the README directory.
    The PoC simulates the interactions between the user, the car, and the server.

### Demonstrating Attacks

The PoC also includes scripts to simulate specific attacks and show how the system's security prevents them.

-   **To run the Replay Attack simulation:**
    ```sh
    python attacks/replay_attack.py
    ```
    *(Observe how the server rejects the replayed command due to an invalid timestamp/nonce.)*

-   **To run the Man-in-the-Middle (MITM) simulation:**
    ```sh
    python attacks/mitm_proxy.py
    ```
    *(Observe how the connection fails because the client and car reject the proxy's invalid certificate.)*

## 👥 Authors

-   [Besar Jukaj](https://github.com/bjukaj)
-   [Francisco Alves](https://github.com/papichickens)
-   [Stefanos Panagoulias](https://github.com/StefanosPanagoulias)
-   [Leonardo Ratti](https://github.com/LRatti)
-   [Furkan Poyraz](https://github.com/furkypoyry)
-   [Maurizio Perriello](https://www.instagram.com/maurizio.perriello/)

## Acknowledgments

-   The project was carried out onder the supervision of Professor **Eric Laermans**.
-   **Ghent University**, Faculty of Engineering and Architecture.
