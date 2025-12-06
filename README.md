# PhishGuard – Email Phishing Intent Analyzer

PhishGuard is a demo web application that analyzes email content and estimates whether an email is **safe, suspicious, or phishing**.  
It uses rule-based NLP logic to detect attacker intent (credential theft, banking fraud, job scams, malware delivery) and assigns a clear **risk score**.

🔗 **Live demo:**  
https://email-phishing-intent-analyzer-5ufy6r9qjytwcntuwr5fdg.streamlit.app/

---

## 🔍 Features

- 📝 **Email content input**
  - Paste any email text (subject + body).
  - Option to load built-in sample phishing emails.

- 🧠 **Intent detection using keywords**
  - Detects categories such as:
    - Credential Theft  
    - Banking Fraud  
    - Job/HR Scam  
    - Payment Scam  
    - Malware Attempt

- 🔗 **Link extraction & risk analysis**
  - Finds all URLs inside the email.
  - Flags risky patterns:
    - IP-based URLs (e.g. `http://192.168.x.x/login`)
    - Suspicious words in URL path (`login`, `verify`, `password`, `update`, `secure`, etc.)
    - `@` symbol in URL (used for obfuscation)
  - Computes a **Link Risk %** with short reasons.

- 📊 **Overall risk scoring**
  - Combines:
    - keyword-based risk  
    - link-based risk  
  - Produces a final **0–100 risk score**:
    - 0–39 → Low Risk  
    - 40–70 → Suspicious  
    - 71–100 → High Risk (Phishing likely)

- 🧾 **Explainability**
  - Highlights suspicious keywords inside an email snippet.
  - Shows why each link is considered risky.

- ✅ **Final decision + safety tips**
  - Displays a summary box:
    - “Low risk / Suspicious / High risk – phishing likely”
  - Shows practical user safety tips (e.g. don’t click links, don’t share passwords, etc.).

- 📥 **Downloadable report**
  - Generates an HTML report containing:
    - risk score  
    - final decision  
    - detected intents  
    - links  
    - suspicious keywords  
    - protection tips  
    - original email snippet

---

## 🛠 Tech Stack

- **Language:** Python  
- **Web framework:** [Streamlit](https://streamlit.io/)  
- **Libraries:**
  - `streamlit` – UI framework
  - `tldextract` – domain extraction from URLs
  - `re` – regular expressions for pattern matching

---

## 📁 Project Structure

```text
email-phishing-intent-analyzer/
├── app.py            # Main Streamlit app
├── requirements.txt  # Python dependencies
└── .gitignore        # Ignore venv and cache files
