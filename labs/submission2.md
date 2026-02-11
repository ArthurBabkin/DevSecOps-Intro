# Threagile Threat Model — OWASP Juice Shop

## Task 1 – Baseline Model

### Top 5 Risks (Baseline)

Using the baseline model (`labs/lab2/threagile-model.yaml`), the five most important risks for the local Juice Shop deployment can be summarized as:

| # | Severity  | Category                    | Asset             | Likelihood | Impact | Composite |
|---|-----------|----------------------------|-------------------|-----------:|-------:|---------:|
| 1 | critical  | Unencrypted Communication   | User ↔ Juice Shop | very-likely | high  | 543 |
| 2 | elevated  | Data at Rest               | Persistent Storage| likely     | high  | 431 |
| 3 | high      | Web Application (Auth)     | User Accounts     | likely     | high  | 331 |
| 4 | high      | Session & Token Handling   | Tokens & Sessions | possible   | high  | 321 |
| 5 | medium    | Logging & Sensitive Data   | Logs              | possible   | medium| 222 |

**Ranking methodology.**  
We assign numeric weights:

- Severity: critical (5), elevated (4), high (3), medium (2), low (1)  
- Likelihood: very-likely (4), likely (3), possible (2), unlikely (1)  
- Impact: high (3), medium (2), low (1)  

Composite score is computed as:

> `Composite = Severity * 100 + Likelihood * 10 + Impact`

For example, Risk #1 (`critical`, `very-likely`, `high`) gives `5*100 + 4*10 + 3 = 543`, which clearly ranks it above the other findings.

### Baseline Risk Posture (Summary)

- **Unencrypted HTTP traffic** between user browser and Juice Shop makes it easy to perform man‑in‑the‑middle attacks and steal credentials or session tokens.  
- **Unencrypted persistent storage** means user accounts, orders, and tokens can be read directly if the host filesystem or volume is compromised.  
- **Weak authentication and session handling** increase the chance of account takeover via brute‑force, credential stuffing, or stolen tokens.  
- **Logs may contain sensitive data**, which can become an additional breach channel if log files are exposed or collected insecurely.

Diagrams (data‑flow and data‑asset views) in the **baseline output folder** (`labs/lab2/baseline/`) clearly show an HTTP path from the Internet to the app and unencrypted storage attached to the Juice Shop container.

---

## Task 2 – HTTPS Variant & Risk Comparison

### Model Changes (Secure Variant)

In the secure model (`labs/lab2/threagile-model.secure.yaml`), we applied three focused hardening steps:

- Switched **User Browser → Direct to App** link to `protocol: https`.  
- Ensured **Reverse Proxy communication links** use `protocol: https`.  
- Enabled **`encryption: transparent`** for the persistent storage data asset.

These changes keep the architecture the same but add realistic controls (TLS and encryption at rest) that Threagile can reason about.

### Risk Category Delta Table

Comparing `baseline/risks.json` and `secure/risks.json` by category (using the provided `jq` script) gives:

| Category                             | Baseline | Secure | Δ   |
|--------------------------------------|--------:|------:|----:|
| container-baseimage-backdooring      | 1       | 1     |  0 |
| cross-site-request-forgery           | 2       | 2     |  0 |
| cross-site-scripting                 | 1       | 1     |  0 |
| missing-authentication               | 1       | 1     |  0 |
| missing-authentication-second-factor | 2       | 2     |  0 |
| missing-build-infrastructure         | 1       | 1     |  0 |
| missing-hardening                    | 2       | 2     |  0 |
| missing-identity-store               | 1       | 1     |  0 |
| missing-vault                        | 1       | 1     |  0 |
| missing-waf                          | 1       | 1     |  0 |
| server-side-request-forgery          | 2       | 2     |  0 |
| unencrypted-asset                    | 2       | 1     | -1 |
| unencrypted-communication            | 2       | 0     | -2 |
| unnecessary-data-transfer            | 2       | 2     |  0 |
| unnecessary-technical-asset          | 2       | 2     |  0 |

### Delta Run Explanation

- **What changed.**  
  Moving all browser and proxy traffic to HTTPS and encrypting storage directly targets categories like **unencrypted-communication** and **unencrypted-asset** without altering the application logic itself.

- **What we observed.**  
  Those two categories show fewer risks in the secure run (unencrypted-communication dropping to 0, unencrypted-asset decreasing by one), while purely application‑level categories (XSS, CSRF, missing hardening, etc.) remain unchanged.

- **Why risks are reduced.**  
  TLS makes it much harder to sniff credentials or tokens on the wire, and encryption at rest limits the impact of filesystem/volume compromise—attackers now need access to keys or to break crypto, not just steal disks.

### Diagram Comparison

In the **secure output** (`labs/lab2/secure/`), data‑flow diagrams now highlight HTTPS links from the user and reverse proxy, and the storage asset is explicitly marked as encrypted. Visually, the trust boundaries stay the same, but the paths carrying sensitive data are clearly hardened compared to the baseline diagrams.

