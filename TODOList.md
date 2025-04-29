# Project TODO List — Smartphone Car Access App (Proof-of-Concept)

We probably don't have to implement all this (inshallah)

## 1. Core System Setup
- [ ] Create basic Python app structure (modules for server, smartphone app, and car system).
- [ ] Setup certificate management (simulate a CA issuing certificates for car and smartphone).
- [ ] Implement local storage simulation (simulate smartphone/car secure storage).

## 2. Authentication Mechanisms
- [ ] Implement **Multi-Factor Authentication** (MFA):
  - [ ] Device possession verification (simulated smartphone ID check).
  - [ ] Biometric verification (mocked FaceID/Fingerprint step).
  - [ ] PIN fallback (backup authentication method).
  - [ ] Risk-based layer (basic simulation, e.g., time/location dummy check).
- [ ] Handle session expiration and re-authentication after inactivity.

## 3. Secure Communication
- [ ] Implement **TLS 1.3** secured communication simulation between:
  - [ ] Smartphone App ↔ Car System.
  - [ ] Smartphone App ↔ Backend Server.
- [ ] Implement **mutual authentication** (digital certificate verification on both sides).
- [ ] Implement **certificate pinning** on smartphone side.

## 4. Command Authentication
- [ ] Implement **challenge-response mechanism**:
  - [ ] Car sends a random nonce.
  - [ ] Smartphone signs the nonce and returns it.
  - [ ] Car verifies the signed nonce.
- [ ] Implement **rolling code mechanism** for commands.

## 5. Access Rights Management
- [ ] Implement secure **Access Sharing**:
  - [ ] Owner generates and sends a **signed delegation token**.
  - [ ] Recipient presents token to car.
  - [ ] Car verifies token validity and recipient’s private key ownership.
- [ ] Implement **Access Revocation**:
  - [ ] Remote revocation by owner.
  - [ ] Automatic revocation if suspicious behavior is detected.

## 6. Driver Identification
- [ ] Simulate **BLE/UWB** proximity check (mocked, assume static or random proximity result).
- [ ] Log driver identity when a delegated token is active.

## 7. Key Management and Storage
- [ ] Simulate **ECC-based** key generation on smartphone/car.
- [ ] Store private keys securely (simulate Secure Enclave/TEE).
- [ ] Simulate certificate-based authentication.

## 8. Attack Mitigations
- [ ] **Man-in-the-Middle Protection**:
  - [ ] TLS + Certificate Pinning.
- [ ] **Replay Attack Protection**:
  - [ ] Challenge-response.
  - [ ] Timestamps and expiry for requests.
- [ ] **Device Theft Mitigation**:
  - [ ] Require biometric unlocking and secure key storage.
  - [ ] Enable remote access revocation.

## 9. Demonstration Features
- [ ] Unlock car (authenticated session required).
- [ ] Start car (authenticated session required).
- [ ] Manage (share/revoke) access rights.
- [ ] Simulate car-server communication for driving license checks.
