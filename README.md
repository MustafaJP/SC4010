# POODLE Attack PoC (SSL 3.0 Protocol)

> **Status:** U/C (under construction)

## About

This is a Group Project for **SC4010 — Applied Cryptography** at Nanyang Technological University (College of Computing and Data Science).

This repository contains a **Proof-of-Concept (PoC)** demonstration of the 2014 **Padding Oracle On Downgraded Legacy Encryption (POODLE)** attack (**CVE-2014-3566**) against **SSL 3.0**. The goal is to make the attack mechanics tangible in a safe, didactic setting.

> **DISCLAIMER**
> This PoC is for education and research only. Do not use it to attack systems you do not own or have explicit permission to test.

---

## How the Demo Works (High-Level)

* **Roles**

  * **Alice** (client) registers with a username & password.
  * **Server** receives ciphertext, performs decryption, padding removal, and HMAC verification.
  * **Eve** (attacker) observes traffic and uses a **padding oracle** to recover plaintext.

* **Crypto model (teaching-friendly)**

  * Simulated **CBC** mode: `P_i = Dec_k(C_i) ⊕ C_{i-1}`.
  * We append an **HMAC** to the plaintext and then apply **PKCS#7 padding** before “encryption.”
  * The block cipher is represented by an **XOR stub** so the algebra is visible (for learning only).

* **Padding-oracle signal**

  * `server_check_padding` returns **True** only if the last *N* bytes of candidate plaintext equal the value *N* (valid PKCS#7).
  * This single-bit signal (valid/invalid) lets Eve solve each plaintext byte, right → left, by tweaking bytes in the **previous** ciphertext block.

* **POODLE loop**

  1. Split `IV || C1 || C2 || … || Cn` and work **backwards** from `Cn` to `C1`.
  2. For each target block `Ci`, brute-force one byte of `C'_{i-1}` until the oracle validates the desired padding.
  3. Use CBC algebra to recover the real plaintext byte; lock solved bytes to enforce the next padding value (`0x01`, then `0x02 0x02`, …).
  4. Repeat for all bytes/blocks → reconstruct full plaintext → **unpad & verify HMAC**.

> **Mitigations (real systems):** Disable SSLv3; use TLS 1.2/1.3 with AEAD (GCM/ChaCha20-Poly1305); ensure uniform error handling to avoid padding-based side-channels.

---

## Getting Started

### Prerequisites

* **Python 3.10–3.12**
* (Recommended) Virtual environment:

  ```bash
  python -m venv .venv
  # macOS/Linux
  source .venv/bin/activate
  # Windows PowerShell
  .venv\Scripts\Activate.ps1
  ```
* Install dependencies:

  ```bash
  pip install -r requirements.txt
  # use pip3 if needed
  ```

### Start the Simulation

```bash
streamlit run page_controller.py
```

App launches at **[http://localhost:8501](http://localhost:8501)**.

#### App Flow

1. **Account Registration Page (Alice)** — enter any username/password (no validation by design). After **Register**, ciphertext is shown in hex (plus password in clear for demo clarity).
2. **Server Page** — click **Registration Logs** to decrypt and display the plaintext (only if HMAC and padding are valid).
3. **Eve’s Control Page** — **Intercept Message** to view captured values; then **Launch Poodle Attack** to step through the oracle and recover plaintext.

---

## Project Structure

```
├── page_controller.py                # routes between Streamlit pages
├── requirements.txt                  # Python dependencies
└── views
    ├── Alice.py                      # client (Alice) page
    ├── Eve.py                        # attacker (Eve) page
    ├── server.py                     # server page
    └── utils
        ├── __init__.py               # marks 'views.utils' as a package
        └── crypto.py                 # unified crypto helpers (CBC/HMAC/oracle)
```

> **Imports**
>
> * `views/Alice.py` → `from views.utils.crypto import cbc_encrypt`
> * `views/server.py` → `from views.utils.crypto import cbc_decrypt`
> * `views/Eve.py` → `from views.utils.crypto import poodle_attack`

---

## Screenshots (Sample)

Replace with your own if desired:

* Registration page (Alice) — ciphertext display
* Server page — decrypted credentials
* Eve page — attack trace & recovered plaintext

---

## Known Limitations

* The XOR “cipher” is **not** a real block cipher; it’s a transparency aid for teaching.
* Real network stacks have more nuanced behavior; this PoC isolates the oracle signal.

---

## Presentation Slides

See **POODLE PoC Presentation_Final.pptx** in the repository root.

---

## References & Further Reading

* [https://github.com/mpgn/poodle-PoC/](https://github.com/mpgn/poodle-PoC/)
* [https://access.redhat.com/articles/1232123](https://access.redhat.com/articles/1232123)
* [https://www.geeksforgeeks.org/block-cipher-modes-of-operation/](https://www.geeksforgeeks.org/block-cipher-modes-of-operation/)
* [https://xilinx.github.io/Vitis_Libraries/security/2020.1/guide_L1/internals/cbc.html](https://xilinx.github.io/Vitis_Libraries/security/2020.1/guide_L1/internals/cbc.html)
* [https://www.acunetix.com/blog/web-security-zone/what-is-poodle-attack/](https://www.acunetix.com/blog/web-security-zone/what-is-poodle-attack/)
* [https://en.wikipedia.org/wiki/POODLE](https://en.wikipedia.org/wiki/POODLE)
* [https://en.wikipedia.org/wiki/Transport_Layer_Security](https://en.wikipedia.org/wiki/Transport_Layer_Security)
* [https://www.techtarget.com/whatis/definition/POODLE-attack](https://www.techtarget.com/whatis/definition/POODLE-attack)
* [https://www.wallarm.com/what/poodle-attack](https://www.wallarm.com/what/poodle-attack)
* [https://www.manageengine.com/key-manager/information-center/what-is-poodle-attack.html](https://www.manageengine.com/key-manager/information-center/what-is-poodle-attack.html)
* [https://paddingoracle.github.io/](https://paddingoracle.github.io/)
* [https://www.youtube.com/watch?v=uDHo-UAM6_4](https://www.youtube.com/watch?v=uDHo-UAM6_4)
* [https://www.youtube.com/watch?v=F0srzSkTO5M&t=290s](https://www.youtube.com/watch?v=F0srzSkTO5M&t=290s)
* [https://www.youtube.com/watch?v=4EgD4PEatA8&t=483s](https://www.youtube.com/watch?v=4EgD4PEatA8&t=483s)
* [https://www.youtube.com/watch?v=0D7OwYp6ZEc](https://www.youtube.com/watch?v=0D7OwYp6ZEc)
