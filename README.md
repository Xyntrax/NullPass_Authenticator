# NullPass Authenticator

A Python TOTP authenticator for managing 2FA codes locally.
Built as a fun open source project to explore TOTP and local encryption, not as a replacement for established authenticators like Bitwarden, KeePassXC, or Aegis.

## Features
- Generate time-based one-time passwords (TOTP)
- Store multiple accounts with AES encryption
- Simple and lightweight GUI
- Runs fully locally on your device

## Requirements

- Python 3.9+
- Dependencies:
  - [pyotp](https://pypi.org/project/pyotp/)
  - [cryptography](https://pypi.org/project/cryptography/)

### Install dependencies:

```
pip install pyotp cryptography
```
