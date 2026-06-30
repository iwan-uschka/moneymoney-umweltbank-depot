# MoneyMoney Umweltbank Depot Extension

Adds Umweltbank depot accounts to [MoneyMoney](https://moneymoney-app.com) via QR-code login (SecureGo plus). Securities and current prices are fetched on every sync.

## Prerequisites

- MoneyMoney 5.x
- An Umweltbank depot account
- SecureGo plus installed and paired with your Umweltbank account
- **QR-code login must be activated once via the browser** at banking.umweltbank.de → Settings → SecureGo plus → QR-Code Login. Without this step SecureGo plus will not recognise the QR code shown by MoneyMoney.

## Installation

1. Download `UmweltbankDepot.lua`
2. Open MoneyMoney → **Help → Show Database in Finder**
3. Copy the file into the `Extensions` folder
4. Restart MoneyMoney
5. Add a new account → search for **Umweltbank Depot**

## Login Flow

Each sync triggers a two-phase authentication. No credentials are stored or transmitted — the extension never sees the PIN.

1. **QR code displayed** — MoneyMoney shows a QR code generated from the server-issued JWT challenge.
2. **Scan in SecureGo plus** — Open the app, scan the code, and confirm the login request on the phone.
3. **Click OK in MoneyMoney** — The extension polls for approval, completes the OAuth flow, and fetches the portfolio.

## Why QR-Code Login

Umweltbank's standard login encrypts credentials with JWE (RSA-OAEP-512 + AES-GCM). Implementing RSA-OAEP in MoneyMoney's Lua sandbox is not feasible, so the QR-code path is used instead. The server issues a short-lived JWT challenge; SecureGo plus signs the approval on the device; the server grants the session without any credential encryption on the extension's side.

The QR code image is generated entirely within the extension in pure Lua: GF(256) arithmetic, Reed-Solomon error correction, full ISO 18004 matrix construction with 8-mask evaluation, and PNG encoding via uncompressed DEFLATE.

## Known Limitations

- **Unsigned extension** — MoneyMoney will warn that the extension is not from a verified developer. You need to explicitly allow unsigned extensions under MoneyMoney → Preferences → Extensions.
- **Dummy credentials required** — The "Add Account" dialog always shows username and password fields. MoneyMoney does not allow extensions to hide or relabel them. Enter any values you like — they are never used or transmitted; authentication happens entirely via QR code.
- **QR code display size** — The challenge dialog renders the QR code smaller than ideal. If your phone camera struggles to scan it, use macOS Accessibility Zoom (System Settings → Accessibility → Zoom) or hold Option and scroll to magnify the relevant area of the screen.
- **First sync** — the holdings endpoint is seeded with an empty positions list. If the server does not populate positions from the account state, a separate initial-holdings endpoint may need to be discovered.
- **Redirect chain** — the portal OAuth redirect chain is followed automatically by MoneyMoney's HTTP client. If auth-code extraction fails, open a GitHub issue with the error message shown by MoneyMoney.
- **Securities only** — transaction history is not available through the portal API.

## Technical Reference

| Component | Detail |
|---|---|
| Auth | QR-code login via Atruvia CAS → portal OAuth 2.0 |
| QR encoder | Pure Lua — GF(256), Reed-Solomon, ISO 18004 |
| PNG encoder | Uncompressed DEFLATE (no zlib available in Lua) |
| EC level | L (Low, ~7% damage recovery) |
| Max JWT size | 1,273 bytes (QR code version 25) |
| Typical JWT size | ~840 bytes → QR code version 20 |
