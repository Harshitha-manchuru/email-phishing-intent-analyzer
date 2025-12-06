

# app.py
import streamlit as st
import re
import tldextract
import base64
from datetime import datetime
from io import BytesIO

# --------- PAGE CONFIG ----------
st.set_page_config(
    page_title="PhishGuard — Email Intent Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --------- CUSTOM CSS (styling) ----------
PAGE_CSS = """
<style>
/* background and card styles */
.stApp {
    background: linear-gradient(180deg, #0f172a 0%, #071032 70%);
    color: #f8fafc;
}
.header {
    padding: 18px 24px;
    border-radius: 12px;
    background: linear-gradient(90deg, rgba(99,102,241,0.12), rgba(16,185,129,0.06));
    margin-bottom: 16px;
}
.card {
    background: rgba(255,255,255,0.04);
    padding: 14px;
    border-radius: 10px;
    box-shadow: 0 4px 20px rgba(2,6,23,0.6);
    margin-bottom: 12px;
}
.small-muted {
    color: #cbd5e1;
    font-size: 0.9em;
}
.badge-danger {
    color: #fff;
    background: #ef4444;
    padding: 6px 10px;
    border-radius: 999px;
    font-weight: 600;
}
.badge-warning {
    color: #0f172a;
    background: #fcd34d;
    padding: 6px 10px;
    border-radius: 999px;
    font-weight: 600;
}
.badge-safe {
    color: #0f172a;
    background: #a7f3d0;
    padding: 6px 10px;
    border-radius: 999px;
    font-weight: 600;
}
.summary-box {
    background: linear-gradient(90deg, rgba(255,255,255,0.03), rgba(255,255,255,0.02));
    padding: 12px;
    border-radius: 10px;
    margin-bottom: 12px;
}
.tip {
    color: #e6eef8;
    font-size: 0.95em;
}
</style>
"""
st.markdown(PAGE_CSS, unsafe_allow_html=True)

# --------- HEADER ----------
st.markdown(
    """
    <div class="header">
      <h2 style="margin:0 0 6px 0;">🛡️ <strong>PhishGuard</strong> — Email Phishing Intent Analyzer</h2>
      <div class="small-muted">Detects attacker intent (credential theft, banking fraud, malware, job scams) and shows a clear risk score — fast demo version.</div>
    </div>
    """,
    unsafe_allow_html=True,
)

# --------- SIDEBAR (controls & samples) ----------
st.sidebar.header("Controls")
use_sample = st.sidebar.checkbox("Use sample email", value=False)
show_explain = st.sidebar.checkbox("Show explainability details", value=True)
risk_link_weight = st.sidebar.slider("Weight for links in risk score", 0, 40, 20)
keyword_weight = st.sidebar.slider("Weight per suspicious keyword", 0, 30, 10)
st.sidebar.markdown("---")
st.sidebar.markdown("**Samples:**")
if st.sidebar.button("Load Sample: Credential Scam"):
    use_sample = True
    sample_choice = "credential"
elif st.sidebar.button("Load Sample: Job Offer Scam"):
    use_sample = True
    sample_choice = "job"
else:
    sample_choice = None
st.sidebar.markdown("---")


# --------- SAMPLE EMAILS ----------
SAMPLES = {
    "credential": """Subject: Security Alert: Verify your account

Dear User,

We detected suspicious activity on your account. Please verify your password immediately at https://secure-login.example.com to avoid suspension.

Best,
Security Team""",
    "job": """Subject: Congratulations — Internship Offer!

Hello,

We are excited to offer you an internship. Please download the attached offer letter and confirm your bank details to receive the stipend.

Regards,
HR Team""",
}

# --------- MAIN LAYOUT (2 columns) ----------
col1, col2 = st.columns([1, 1.1])

with col1:
    st.subheader("1) Paste Email Content")
    if use_sample:
        # if sidebar button was pressed, set according sample_choice
        if sample_choice is None:
            sample_choice = "credential"
        st.text_area("Email text", value=SAMPLES.get(sample_choice, SAMPLES["credential"]), height=320, key="email_input")
    else:
        st.text_area("Email text", value="", height=320, key="email_input")
    st.write("**Tip:** Paste full email text including subject and from: headers for better results.")
    st.markdown("---")
    st.subheader("Quick actions")
    col_a, col_b = st.columns(2)
    with col_a:
        st.button("Clear", key="clear_btn")
    with col_b:
        st.button("Run Analysis", key="run_btn")  # We'll trigger with a separate 'Analyze' below

with col2:
    st.subheader("2) Analysis & Results")
    # placeholder boxes
    results_box = st.empty()

# --------- ANALYZER LOGIC ----------
# Categories + suspicious keywords (you can extend)
CATEGORIES = {
    "Credential Theft": ["password", "verify", "account", "login", "reset", "confirm", "security alert"],
    "Banking Fraud": ["bank", "transaction", "blocked", "atm", "statement", "suspended", "account number"],
    "Job/HR Scam": ["offer letter", "internship", "hiring", "salary", "vacancy", "download attached"],
    "Payment Scam": ["payment", "invoice", "unpaid", "due", "lottery", "winning", "transfer"],
    "Malware Attempt": ["attachment", "download", "exe", "zip", "install", "update", ".exe", ".zip"],
}

def extract_links(text):
    # find http(s) links and also pseudo links
    pattern = r'(https?://[^\s\'"<>]+)'
    raw = re.findall(pattern, text)
    # also catch things like secure-login[.]example[.]com (simple)
    alt = re.findall(r'([a-zA-Z0-9\-]+\[?\.\]?[a-zA-Z0-9\-\.\[]+\.[a-zA-Z]{2,})', text)
    return list(dict.fromkeys(raw + alt))  # unique

# ---- Inserted simple link risk function (easy to understand) ----
def link_risk(link):
    risk = 0
    link_lower = link.lower()

    # If link uses an IP address (e.g., http://192.168.0.1/...)
    if re.match(r"https?://\d+\.\d+\.\d+\.\d+", link_lower):
        risk += 40

    # Suspicious words in path or domain
    suspicious_words = ["login", "verify", "account", "update", "password", "secure", "confirm", "signin"]
    for w in suspicious_words:
        if w in link_lower:
            risk += 15

    # If '@' is present in link (obfuscation technique)
    if "@" in link:
        risk += 20

    # cap at 100
    if risk > 100:
        risk = 100

    return risk

def highlight_words(text, words):
    out = text
    for w in set(words):
        out = re.sub("(?i)("+re.escape(w)+")", r"<mark>\1</mark>", out)
    return out

# ---- UPDATED compute_risk: combines keyword + link risks ----
def compute_risk(text, kw_weight=10, link_weight=20):
    score = 0
    found_keywords = []

    # keyword-based scoring
    for cat, kwlist in CATEGORIES.items():
        for kw in kwlist:
            if kw.lower() in text.lower():
                found_keywords.append((kw, cat))
                score += kw_weight

    # extract links
    links = extract_links(text)

    # add link weight if links exist
    if links:
        score += link_weight  # base link weight

        # extra scoring: add link_risk for each extracted link
        for link in links:
            # limit contribution per link to avoid huge jumps
            score += min(link_risk(link), 30)

    # cap at 100
    if score > 100:
        score = 100

    return score, found_keywords, links

# --------- TRIGGER ANALYSIS ----------
email_text = st.session_state.get("email_input", "")
analyze = st.button("Analyze")  # main analyze button under results

def _final_decision_and_tips(score, detected_categories, links, found_keywords):
    """
    Returns a tuple (decision_text, tips_list, level) where level is 'safe','suspicious','high'
    """
    if score > 70:
        decision = "⚠️ HIGH RISK — PHISHING LIKELY"
        tips = [
            "Do NOT click any links or open attachments.",
            "Do NOT reply or provide personal/banking information.",
            "Report the email to your IT/security team or mark as phishing in your email client.",
            "If you already clicked a link, immediately change your passwords and enable 2FA."
        ]
        level = "high"
    elif score >= 40:
        decision = "⚠ SUSPICIOUS — EXERCISE CAUTION"
        tips = [
            "Avoid clicking links; verify sender through other channels (call/official website).",
            "Do not share personal or financial details via reply.",
            "Check sender's email address carefully and look for spelling/typos.",
            "When in doubt, consult your IT/security team."
        ]
        level = "suspicious"
    else:
        decision = "✅ LOW RISK — PROBABLE SAFE EMAIL"
        tips = [
            "Still exercise normal caution (do not share passwords).",
            "If unsure about attachments, verify sender first.",
            "Keep software and antivirus up to date."
        ]
        level = "safe"
    return decision, tips, level

if analyze and email_text.strip() == "":
    st.warning("Please paste email text before analyzing.")
elif analyze:
    score, found_keywords, links = compute_risk(email_text, kw_weight=keyword_weight, link_weight=risk_link_weight)

    # intent categories present
    detected_categories = sorted(set([cat for (kw, cat) in found_keywords]))

    # build results display
    with results_box.container():
        # SUMMARY (stylish with tips) - Step 4 selection "C"
        decision_text, tips, level = _final_decision_and_tips(score, detected_categories, links, found_keywords)
        st.markdown('<div class="summary-box">', unsafe_allow_html=True)
        st.markdown(f"### {decision_text}")
        st.write(f"**Overall Risk Score:** {score}%")
        if detected_categories:
            st.write("**Detected Intents:** " + ", ".join(detected_categories))
        else:
            st.write("**Detected Intents:** None")
        # show link summary
        if links:
            st.write(f"**Links Found:** {len(links)}  —  " + ", ".join([tldextract.extract(l).registered_domain or l for l in links]))
        else:
            st.write("**Links Found:** None")
        st.markdown("<hr/>", unsafe_allow_html=True)
        st.write("**Suggested Actions / Protection Tips:**")
        for t in tips:
            st.markdown(f"- {t}")
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown('<div class="card">', unsafe_allow_html=True)
        # top row: risk meter + short summary
        r1, r2 = st.columns([1.4, 1])
        with r1:
            st.metric("Overall Risk Score", f"{score}%", delta=None)
            # color meter using a progress bar
            st.progress(int(score))
            if score >= 70:
                st.markdown('<div class="badge-danger">High Risk — Do not click links</div>', unsafe_allow_html=True)
            elif score >= 40:
                st.markdown('<div class="badge-warning" style="background:#f97316">Medium Risk</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="badge-safe">Low Risk</div>', unsafe_allow_html=True)

        with r2:
            st.write("**Detected intents:**")
            if detected_categories:
                for c in detected_categories:
                    st.write("• " + c)
            else:
                st.write("• No clear malicious intent found")

        st.markdown("</div>", unsafe_allow_html=True)

        # Links card (with simple per-link risk)
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.subheader("🔗 Extracted Links")
        if links:
            for link in links:
                try:
                    te = tldextract.extract(link)
                    domain = te.registered_domain or link
                except Exception:
                    domain = link
                # compute simple link risk and show reasons
                link_score = link_risk(link)
                st.write(f"- {link}  —  `{domain}`  (Link Risk: **{link_score}%**)")
                # show short reasons for higher scores
                reasons = []
                if re.match(r"https?://\d+\.\d+\.\d+\.\d+", link.lower()):
                    reasons.append("IP address in URL")
                if "@" in link:
                    reasons.append("'@' in URL")
                found_path_words = [w for w in ["login","verify","account","update","password","secure","confirm","signin"] if w in link.lower()]
                if found_path_words:
                    reasons.append("suspicious words: " + ", ".join(found_path_words))
                if reasons:
                    st.caption("Reasons: " + "; ".join(reasons))
        else:
            st.write("No links found.")
        st.markdown("</div>", unsafe_allow_html=True)

        # Suspicious keywords card
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.subheader("⚠ Suspicious Keywords Found")
        if found_keywords:
            for kw, cat in found_keywords:
                st.write(f"- **{kw}**  (category: {cat})")
        else:
            st.write("None")
        st.markdown("</div>", unsafe_allow_html=True)

        # Explainability / highlighted excerpt
        if show_explain:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.subheader("🧾 Explainability")
            try:
                snippet = email_text.strip().replace("\n", " ")[:800] + ("..." if len(email_text) > 800 else "")
                highlighted = highlight_words(snippet, [w for w, _ in found_keywords])
                st.markdown(highlighted, unsafe_allow_html=True)
            except Exception:
                st.write(snippet)
            st.markdown("</div>", unsafe_allow_html=True)

        # Downloadable report (simple HTML report)
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.subheader("📥 Download Report")
        report_html = f"""
        <html><body>
        <h2>PhishGuard Report</h2>
        <p><strong>Date:</strong> {datetime.utcnow().isoformat()} UTC</p>
        <p><strong>Final Decision:</strong> {decision_text}</p>
        <p><strong>Risk Score:</strong> {score}%</p>
        <p><strong>Detected Intents:</strong> {', '.join(detected_categories) or 'None'}</p>
        <p><strong>Links:</strong></p><ul>
        {''.join(f'<li>{l}</li>' for l in links) if links else '<li>None</li>'}
        </ul>
        <p><strong>Keywords:</strong></p><ul>
        {''.join(f'<li>{kw} ({cat})</li>' for kw,cat in found_keywords) if found_keywords else '<li>None</li>'}
        </ul>
        <h4>Suggested Actions / Protection Tips</h4>
        <ul>
        {''.join(f'<li>{t}</li>' for t in tips)}
        </ul>
        <hr/>
        <h4>Original Snippet</h4>
        <pre style="white-space:pre-wrap;">{email_text[:1000]}</pre>
        </body></html>
        """
        b = report_html.encode("utf-8")
        st.download_button("Download HTML report", data=b, file_name="phishguard_report.html", mime="text/html")
        st.markdown("</div>", unsafe_allow_html=True)

    # also show a short footer note
    st.markdown("----")
    st.info("This is a demo/prototype. For production, integrate datasets, model-based classification, and email header checks.")
