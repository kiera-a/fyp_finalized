from multiprocessing import reduction
import re
import hashlib
import pandas as pd
from collections import defaultdict

# ---------- GRC SECTOR RULES ----------
SECTOR_RULES = {
    "banking": {
        "label": "Banking / Finance",
        "regulators": "MAS Technology Risk Management Guidelines + Singapore PDPA",
        "description": "Protects customer financial identifiers, payment details and confidential financial data.",
        "keywords": ["bank", "bank_account", "account number", "paynow", "credit_card", "credit card", "salary", "income", "transaction", "customer_id", "loan", "balance"],
        "items": {
            "name": {"label": "Customer Name", "technique": "Pseudonymisation", "risk": "Can identify the customer.", "severity": "Medium"},
            "email": {"label": "Email Address", "technique": "Email Masking", "risk": "Can identify or contact the customer.", "severity": "Medium"},
            "phone": {"label": "Phone / PayNow Number", "technique": "Phone Masking", "risk": "Can expose PayNow-linked identity and contact details.", "severity": "High"},
            "bank_account": {"label": "Bank Account Number", "technique": "Masking", "risk": "Can expose financial account details.", "severity": "High"},
            "credit_card": {"label": "Credit Card Number", "technique": "Masking", "risk": "Can be misused for payment fraud.", "severity": "High"},
            "customer_id": {"label": "Customer ID", "technique": "Hashing", "risk": "Can link records back to a customer.", "severity": "Medium"},
            "salary": {"label": "Salary / Income", "technique": "Generalisation", "risk": "Confidential financial information.", "severity": "Medium"},
            "password": {"label": "Password", "technique": "Redaction", "risk": "Can lead to account compromise.", "severity": "Critical"},
        }
    },
    "healthcare": {
        "label": "Healthcare",
        "regulators": "MOH Healthcare guidance + Singapore PDPA",
        "description": "Protects patient identifiers, medical records and diagnosis information.",
        "keywords": ["patient", "patient_id", "medical", "medical_record", "mrn", "diagnosis", "doctor", "clinic", "hospital", "nric", "age"],
        "items": {
            "name": {"label": "Patient Name", "technique": "Pseudonymisation", "risk": "Can identify the patient.", "severity": "High"},
            "nric": {"label": "NRIC / FIN", "technique": "Redaction", "risk": "Strong national identifier.", "severity": "Critical"},
            "email": {"label": "Email Address", "technique": "Email Masking", "risk": "Can identify or contact patient.", "severity": "Medium"},
            "phone": {"label": "Phone Number", "technique": "Phone Masking", "risk": "Can identify or contact patient.", "severity": "Medium"},
            "patient_id": {"label": "Patient ID", "technique": "Hashing", "risk": "Can link records to a patient.", "severity": "High"},
            "medical_record": {"label": "Medical Record Number", "technique": "Hashing", "risk": "Can link to health records.", "severity": "High"},
            "diagnosis": {"label": "Diagnosis", "technique": "Suppression", "risk": "Reveals personal health condition.", "severity": "Critical"},
            "age": {"label": "Age", "technique": "Generalisation", "risk": "Can contribute to re-identification.", "severity": "Medium"},
            "password": {"label": "Password", "technique": "Redaction", "risk": "Can lead to system compromise.", "severity": "Critical"},
        }
    },
    "it": {
        "label": "IT / Cybersecurity",
        "regulators": "Cybersecurity best practices + Singapore PDPA",
        "description": "Protects credentials, internal infrastructure details and system information.",
        "keywords": ["password", "api_key", "api key", "secret", "token", "server", "ip_address", "ip address", "version", "username", "admin"],
        "items": {
            "name": {"label": "Employee Name", "technique": "Pseudonymisation", "risk": "Can identify internal staff.", "severity": "Medium"},
            "email": {"label": "Email Address", "technique": "Email Masking", "risk": "Can be used for phishing.", "severity": "Medium"},
            "username": {"label": "Username", "technique": "Hashing", "risk": "Can support account targeting.", "severity": "Medium"},
            "password": {"label": "Password", "technique": "Redaction", "risk": "Can lead to unauthorized access.", "severity": "Critical"},
            "ip": {"label": "Internal IP Address", "technique": "IP Truncation", "risk": "Exposes internal network information.", "severity": "High"},
            "api_key": {"label": "API Key / Token", "technique": "Redaction", "risk": "Can allow unauthorized API access.", "severity": "Critical"},
            "version": {"label": "System Version", "technique": "Generalisation", "risk": "Can reveal vulnerable software versions.", "severity": "Medium"},
            "secret": {"label": "Secret Records", "technique": "Suppression", "risk": "May contain confidential internal information.", "severity": "Critical"},
        }
    }
}

# ---------- PATTERNS ----------
email_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
phone_pattern = r'\b[689]\d{7}\b'
ip_pattern = r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'
password_pattern = r'(?i)\b(password|pass|pwd)\b\s*[=:]?\s*\S+'
nric_pattern = r'\b[STFG]\d{7}[A-Z]\b'
age_pattern = r'(?i)\bage\b\s*[=:]?\s*(\d{1,3})'
version_pattern = r'(?i)\b(?:version|ver)\b\s*[=:]?\s*v?\d+(?:\.\d+)+'
customer_id_pattern = r'(?i)\b(?:customer[_\s-]?id|cust[_\s-]?id|ID)\b\s*[=:]?\s*([A-Z0-9_-]+)'
patient_id_pattern = r'(?i)\bpatient[_\s-]?id\b\s*[=:]?\s*([A-Z0-9_-]+)'
medical_record_pattern = r'(?i)\b(?:medical[_\s-]?record|MRN)\b\s*[=:]?\s*([A-Z0-9_-]+)'
api_key_pattern = r'(?i)\b(?:api[_\s-]?key|token|secret[_\s-]?key)\b\s*[=:]?\s*[A-Za-z0-9_\-]{6,}'
bank_account_pattern = r'(?i)\b(?:bank[_\s-]?account|account[_\s-]?number|acct)\b\s*[=:]?\s*(\d{8,14})'
credit_card_pattern = r'\b(?:\d[ -]*?){13,16}\b'
salary_pattern = r'(?i)\b(?:salary|income|monthly salary|annual salary)\b\s*[=:]?\s*\$?\d{3,8}'
diagnosis_pattern = r'(?i)\b(diabetes|hypertension|asthma|covid|flu|cancer)\b'
secret_line_pattern = r'(?im)^.*\bSECRET\b.*$'
name_pattern = re.compile(r'\b(John|Sarah|Michael|Aaliyah|David|Ahmad|Siti|Ravi|Mei|Wei|Priya|Kumar|Hassan|Nurul|Farah|Aisha|Benjamin|Jessica|Daniel|Marcus|Jasmine|Ethan|Rachel|Joshua|Stephanie|Ryan|Michelle|Kevin|Amanda|Brandon|Cheryl|Samuel|Vanessa|Patrick|Christine|Jane|Lim|Tan|Lee|Ng)\b')

_token_map = {}
_token_counter = 1

def _reset_tokens():
    global _token_map, _token_counter
    _token_map = {}
    _token_counter = 1

def _pseudonymize_name(name):
    global _token_counter
    if name not in _token_map:
        _token_map[name] = f"USER{_token_counter:03}"
        _token_counter += 1
    return _token_map[name]

def hash_data(data):
    return hashlib.sha256(str(data).encode()).hexdigest()[:12]

def mask_phone(phone):
    return str(phone)[:4] + "****"

def mask_email(email):
    username, domain = email.split("@", 1)
    return username[0] + "*" * min(len(username)-1, 5) + "@" + domain

def truncate_ip(ip):
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.xxx.xxx"

def mask_account(value):
    s = re.sub(r'\D', '', str(value))
    if len(s) <= 4:
        return "XXXX"
    return "X" * (len(s)-4) + s[-4:]

def generalize_age_value(age):
    age = int(age)
    if age <= 9: return "0-9"
    if age <= 19: return "10-19"
    if age <= 29: return "20-29"
    if age <= 39: return "30-39"
    if age <= 49: return "40-49"
    if age <= 59: return "50-59"
    if age <= 69: return "60-69"
    return "70+"

def generalize_salary_value(value):
    try:
        v = int(float(re.sub(r'[^0-9.]', '', str(value))))
        low = (v // 1000) * 1000
        high = low + 999
        return f"${low//1000}k-${high//1000}k"
    except Exception:
        return "[SALARY BAND]"

def normalize_col(col):
    return str(col).strip().lower().replace(" ", "_").replace("-", "_")

COLUMN_ALIASES = {
    "name": ["name", "customer_name", "patient_name", "employee_name", "full_name"],
    "email": ["email", "email_address"],
    "phone": ["phone", "phone_number", "mobile", "paynow", "paynow_number"],
    "bank_account": ["bank_account", "account_number", "acct", "bank_acct"],
    "credit_card": ["credit_card", "card_number", "debit_card"],
    "customer_id": ["customer_id", "cust_id"],
    "salary": ["salary", "income", "monthly_salary", "annual_salary"],
    "password": ["password", "pass", "pwd"],
    "nric": ["nric", "fin"],
    "patient_id": ["patient_id"],
    "medical_record": ["medical_record", "medical_record_number", "mrn"],
    "diagnosis": ["diagnosis", "condition"],
    "age": ["age"],
    "username": ["username", "user"],
    "ip": ["ip", "ip_address", "server_ip"],
    "api_key": ["api_key", "token", "secret_key"],
    "version": ["version", "system_version"],
    "secret": ["secret", "confidential"],
}

def detect_sector(text, columns=None):
    scores = {"banking": 0, "healthcare": 0, "it": 0}
    matches = {"banking": [], "healthcare": [], "it": []}

    search_text = (text or "").lower()

    if columns:
        search_text += " " + " ".join(normalize_col(c) for c in columns)

    for sector, rules in SECTOR_RULES.items():
        for kw in rules["keywords"]:
            if kw.lower().replace(" ", "_") in search_text or kw.lower() in search_text:
                scores[sector] += 1
                matches[sector].append(kw)

    max_score = max(scores.values())

    # Keep sectors that are reasonably close to the best match
    threshold = max(1, int(max_score * 0.5))

    detected = [
        sector
        for sector, score in scores.items()
        if score >= threshold
    ]

    # Default if nothing matched
    if not detected:
        detected = ["banking"]

    return detected, scores, matches

def count_column_matches(df, item_key):
    if df is None:
        return 0
    aliases = COLUMN_ALIASES.get(item_key, [])
    cols = [normalize_col(c) for c in df.columns]
    count = 0
    for i, col in enumerate(cols):
        if col in aliases:
            try:
                count += int(df.iloc[:, i].astype(str).str.strip().ne("").sum())
            except Exception:
                count += len(df)
    return count

def detect_sensitive(text, sectors=None, df=None):
    print("DF IS NONE:", df is None)

    if df is not None:
        print(df.columns.tolist())

    if sectors is None:
        sectors = ["banking"]

    if isinstance(sectors, str):
        sectors = [sectors]

    found = {}

    pattern_counts = {
        "name": len(name_pattern.findall(text or "")),
        "email": len(re.findall(email_pattern, text or "")),
        "phone": len(re.findall(phone_pattern, text or "")),
        "ip": len(re.findall(ip_pattern, text or "")),
        "password": len(re.findall(password_pattern, text or "", re.IGNORECASE)),
        "nric": len(re.findall(nric_pattern, text or "")),
        "age": len(re.findall(age_pattern, text or "", re.IGNORECASE)),
        "version": len(re.findall(version_pattern, text or "", re.IGNORECASE)),
        "customer_id": len(re.findall(customer_id_pattern, text or "", re.IGNORECASE)),
        "patient_id": len(re.findall(patient_id_pattern, text or "", re.IGNORECASE)),
        "medical_record": len(re.findall(medical_record_pattern, text or "", re.IGNORECASE)),
        "api_key": len(re.findall(api_key_pattern, text or "", re.IGNORECASE)),
        "bank_account": len(re.findall(bank_account_pattern, text or "", re.IGNORECASE)),
        "credit_card": len(re.findall(credit_card_pattern, text or "")),
        "salary": len(re.findall(salary_pattern, text or "", re.IGNORECASE)),
        "diagnosis": len(re.findall(diagnosis_pattern, text or "", re.IGNORECASE)),
        "secret": len(re.findall(secret_line_pattern, text or "", re.IGNORECASE)),
        "username": 0,
    }

    allowed = set()

    for sector in sectors:
        allowed.update(SECTOR_RULES.get(sector, {}).get("items", {}).keys())

    for key in allowed:
        total = pattern_counts.get(key, 0) + count_column_matches(df, key)

        if total > 0:
            found[key] = total

    return found

def anonymize_text(text, selected_items=None):
    selected_items = set(selected_items or [])
    changes = 0
    text = str(text)

    if "nric" in selected_items:
        text, n = re.subn(nric_pattern, "[NRIC REDACTED]", text); changes += n
    if "password" in selected_items:
        text, n = re.subn(password_pattern, "password:[REDACTED]", text, flags=re.IGNORECASE); changes += n
    if "api_key" in selected_items:
        text, n = re.subn(api_key_pattern, "API_KEY:[REDACTED]", text, flags=re.IGNORECASE); changes += n
    if "email" in selected_items:
        vals = re.findall(email_pattern, text)
        for v in set(vals): text = text.replace(v, mask_email(v))
        changes += len(vals)
    if "phone" in selected_items:
        vals = re.findall(phone_pattern, text)
        for v in set(vals): text = text.replace(v, mask_phone(v))
        changes += len(vals)
    if "ip" in selected_items:
        vals = re.findall(ip_pattern, text)
        for v in set(vals): text = text.replace(v, truncate_ip(v))
        changes += len(vals)
    if "bank_account" in selected_items:
        def repl_acct(m): return m.group(0).replace(m.group(1), mask_account(m.group(1)))
        text, n = re.subn(bank_account_pattern, repl_acct, text, flags=re.IGNORECASE); changes += n
    if "credit_card" in selected_items:
        vals = re.findall(credit_card_pattern, text)
        for v in set(vals): text = text.replace(v, mask_account(v))
        changes += len(vals)
    if "name" in selected_items:
        vals = name_pattern.findall(text)
        for v in sorted(set(vals), key=len, reverse=True): text = text.replace(v, _pseudonymize_name(v))
        changes += len(vals)
    if "customer_id" in selected_items:
        text, n = re.subn(customer_id_pattern, lambda m: m.group(0).replace(m.group(1), "ID_HASH:" + hash_data(m.group(1))), text, flags=re.IGNORECASE); changes += n
    if "patient_id" in selected_items:
        text, n = re.subn(patient_id_pattern, lambda m: m.group(0).replace(m.group(1), "PATIENT_HASH:" + hash_data(m.group(1))), text, flags=re.IGNORECASE); changes += n
    if "medical_record" in selected_items:
        text, n = re.subn(medical_record_pattern, lambda m: m.group(0).replace(m.group(1), "MRN_HASH:" + hash_data(m.group(1))), text, flags=re.IGNORECASE); changes += n
    if "username" in selected_items:
        text, n = re.subn(r'(?i)\busername\b\s*[=:]?\s*(\w+)', lambda m: "Username: USER_HASH:" + hash_data(m.group(1)), text); changes += n
    if "age" in selected_items:
        text, n = re.subn(age_pattern, lambda m: "Age: " + generalize_age_value(m.group(1)), text, flags=re.IGNORECASE); changes += n
    if "salary" in selected_items:
        text, n = re.subn(salary_pattern, lambda m: re.sub(r'\$?\d{3,8}', generalize_salary_value(m.group(0)), m.group(0)), text, flags=re.IGNORECASE); changes += n
    if "version" in selected_items:
        text, n = re.subn(version_pattern, "Version:vX.X.X", text, flags=re.IGNORECASE); changes += n
    if "diagnosis" in selected_items:
        text, n = re.subn(diagnosis_pattern, "Diagnosis:[REDACTED]", text, flags=re.IGNORECASE); changes += n
    if "secret" in selected_items:
        lines = text.splitlines(); filtered = [l for l in lines if "SECRET" not in l.upper()]
        changes += len(lines) - len(filtered); text = "\n".join(filtered)
    return text, changes

def anonymize_dataframe(df, selected_items):
    _reset_tokens()
    selected_items = set(selected_items or [])
    # Build each anonymised column, then assemble a fresh DataFrame in one step.
    # Rebuilding (instead of mutating column-by-column) keeps the transform
    # Copy-on-Write safe and avoids pandas chained-assignment/dtype warnings.
    new_cols = {}
    for col in df.columns:
        key = None
        ncol = normalize_col(col)
        for item, aliases in COLUMN_ALIASES.items():
            if ncol in aliases:
                key = item; break
        series = df[col]
        if key in selected_items:
            if key == "name":
                new = series.astype(str).map(lambda x: _pseudonymize_name(x))
            elif key in ["password", "api_key", "diagnosis", "secret", "nric"]:
                new = pd.Series(["[REDACTED]"] * len(df), index=df.index)
            elif key in ["phone"]:
                new = series.astype(str).map(mask_phone)
            elif key in ["bank_account", "credit_card"]:
                new = series.astype(str).map(mask_account)
            elif key in ["customer_id", "patient_id", "medical_record", "username"]:
                new = series.astype(str).map(lambda x: "HASH:" + hash_data(x))
            elif key == "age":
                new = series.astype(str).map(lambda x: generalize_age_value(re.sub(r'\D', '', x) or 0))
            elif key == "salary":
                new = series.astype(str).map(generalize_salary_value)
            elif key == "ip":
                new = series.astype(str).map(lambda x: truncate_ip(x) if re.match(ip_pattern, x) else x)
            elif key == "version":
                new = pd.Series(["vX.X.X"] * len(df), index=df.index)
            else:
                new = series
        else:
            new = series.map(lambda x: anonymize_text(x, selected_items)[0])
        new_cols[col] = new
    return pd.DataFrame(new_cols, index=df.index)

def risk_dashboard(before_counts, after_counts, sectors, selected_items=None):
    """
    Creates a GRC-style risk dashboard.

    Important:
    The after-risk should measure residual disclosure risk after the selected
    anonymisation techniques are applied. Some protected values may still match
    a pattern after masking (for example, j****@email.com is still email-shaped),
    so selected protected fields are treated as reduced residual risk instead
    of full original risk.
    """
    selected_items = set(selected_items or [])
    rules = {}

    for sector in sectors:
        rules.update(SECTOR_RULES[sector]["items"])
    rows = []

    severity_weights = {
        "Low": 5,
        "Medium": 10,
        "High": 18,
        "Critical": 25,
    }

    # Residual risk after each technique. Lower = safer.
    residual_factor = {
        "Redaction": 0.02,
        "Suppression": 0.02,
        "Hashing": 0.08,
        "Pseudonymisation": 0.15,
        "Masking": 0.20,
        "Phone Masking": 0.20,
        "Email Masking": 0.25,
        "IP Truncation": 0.30,
        "Generalisation": 0.35,
    }

    technique_effectiveness = {
    "Redaction": 1.00,
    "Suppression": 1.00,
    "Hashing": 0.98,
    "Pseudonymisation": 0.95,
    "Masking": 0.93,
    "Phone Masking": 0.93,
    "Email Masking": 0.90,
    "IP Truncation": 0.88,
    "Generalisation": 0.85,
    }

    score_before = 0.0
    score_after = 0.0

    for key, meta in rules.items():
        before = int(before_counts.get(key, 0))
        raw_after = int(after_counts.get(key, 0))
        sev = meta.get("severity", "Medium")
        technique = meta.get("technique", "Masking")
        weight = severity_weights.get(sev, 10)

        before_score = before * weight

        if key in selected_items and before > 0:
            # If user selected protection, calculate residual risk based on
            # technique strength instead of raw pattern count.
            factor = residual_factor.get(technique, 0.25)
            after_score = before_score * factor
            display_after = raw_after
        else:
            # If user did not protect it, remaining detected data stays risky.
            after_score = raw_after * weight
            display_after = raw_after

        score_before += before_score
        score_after += after_score

        rows.append({
            "key": key,
            "label": meta["label"],
            "severity": meta["severity"],
            "before": before,
            "after": display_after,
            "technique": meta["technique"],
            "status": "Protected" if key in selected_items and before > 0 else "Not selected"
        })

    reduction = 0 if score_before == 0 else round(max(0, (score_before - score_after) / score_before) * 100, 1)

    def level(score, baseline):
        if baseline <= 0:
            return "Low"
        percentage = (score / baseline) * 100
        if percentage >= 70:
            return "High"
        if percentage >= 35:
            return "Medium"
        return "Low"
    
    level_before = "High" if score_before >= 70 else "Medium" if score_before >= 25 else "Low"
    level_after = level(score_after, score_before)

    if selected_items:
        effectiveness_scores = []

        for key in selected_items:
            if key in rules:
                technique = rules[key]["technique"]
                effectiveness_scores.append(
                    technique_effectiveness.get(technique, 0.90)
                )

        avg_effectiveness = (
            sum(effectiveness_scores) / len(effectiveness_scores)
            if effectiveness_scores else 0.90
        )
    else:
        avg_effectiveness = 0.90

    compliance_score = round(
        reduction + (100 - reduction) * avg_effectiveness,
        1
    )

    compliance_score = min(compliance_score, 100)

    return {
        "rows": rows,
        "score_before": round(score_before, 1),
        "score_after": round(score_after, 1),
        "reduction": reduction,
        "level_before": level_before,
        "level_after": level_after,
        "compliance_score": compliance_score
    }

def k_anonymity_preview(df):
    if df is None or df.empty:
        return None
    quasi = [c for c in df.columns if normalize_col(c) in ["age", "postcode", "gender", "occupation", "race"]]
    if not quasi:
        return {"available": False, "message": "No common quasi-identifiers found for k-anonymity preview."}
    groups = df.astype(str).groupby(quasi).size()
    k = int(groups.min()) if not groups.empty else 0
    risk = "High" if k <= 1 else "Medium" if k < 3 else "Low"
    return {"available": True, "quasi_identifiers": quasi, "k": k, "risk": risk}
