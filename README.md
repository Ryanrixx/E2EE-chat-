# End-to-End Encrypted Chat App  
Secure Client-to-Client Messaging using RSA-OAEP + AES-GCM

##  Overview
This project is a fully functional secure communication system featuring:
End-to-end encryption 
Client-side RSA-OAEP key generation  
Hybrid cryptography (AES-256-GCM + RSA-2048)  
Encrypted server acknowledgements  
Real-time messaging with Socket.IO  

All secrets remain in the browser — no plaintext messages ever touch the server.

##  Technology Stack
| Layer | Technology |
|------|------------|
| Frontend | HTML, CSS, JS, WebCrypto API |
| Backend | Node.js + Express |
| Real-Time | Socket.IO |
| Crypto | AES-GCM, RSA-OAEP, SHA-256 |

##  Security Design

| Component | Role |
|----------|-----|
| RSA-2048 | Encrypts AES key securely |
| AES-GCM | Encrypts actual message with authentication tag |
| WebCrypto API | Ensures strong, browser-native crypto |
| Server | Stores only public keys, relays encrypted payload |

The **server cannot read messages** because:
- Only clients hold private RSA keys
- AES session keys are encrypted before delivery

Confidentiality secured  
Public key authenticity depends on server (MitM scenario not protected in this version)

### Dependencies
- express ^4.18.2
- socket.io ^4.7.2

### Install Dependencies

```sh
npm install

