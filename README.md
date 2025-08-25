# NullPass Authenticator

A Python TOTP authenticator for managing 2FA codes locally.
This project provides a simple open source alternative to mobile authenticators, running directly on your desktop.

## Features
- Generate time-based one-time passwords (TOTP)
- Store multiple accounts securely with AES encryption
- Simple and lightweight GUI (no bloat)
- Runs fully locally on your device

## Requirements

- Python 3.9+
- Dependencies:
  - [pyotp](https://pypi.org/project/pyotp/)
  - [cryptography](https://pypi.org/project/cryptography/)

### Install dependencies:

```sh
pip install pyotp cryptography
```
