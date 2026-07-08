# AI-Powered Privileged Access Anomaly Detection

A proof-of-concept system that detects anomalous privileged-session behavior
(the kind of thing PAM/UEBA platforms like ARCON, CyberArk, or BeyondTrust
monitor) and uses an LLM to auto-generate SOC-analyst-style triage notes for
each flagged session.

## What this project actually does (plain English)

1. **Simulates privileged sessions** — admin/root/service-account logins,
   like what a PAM system would record: who logged in, when, from where,
   what they accessed, how long, how many privilege escalations.
2. **Learns "normal" behavior per user** — usual login hours, usual
   location, usual activity volume.
3. **Flags sessions that deviate from normal** using Isolation Forest, an
   unsupervised anomaly detection algorithm. Unsupervised means it never
   sees labeled "attack" examples — it only learns what's typical and
   flags what isn't. This matters because in the real world you almost
   never have labeled insider-threat/PAM-abuse data to train on.
4. **AI triage layer** — every flagged session gets sent to an LLM (via
   Groq's free API) which writes a plain-English explanation of why it's
   risky, maps it to a likely MITRE ATT&CK technique, and recommends a
   next action — mimicking what an actual SOC L1 analyst would write in
   a ticket.
5. **Dashboard** — a Streamlit app to visually browse flagged sessions
   and drill into any one of them.

## Why this maps to real PAM/UEBA products

Privileged Access Management platforms exist specifically to answer the
question this project answers: "is this privileged session behaving the
way it normally does, and if not, why?" This project is a scaled-down,
transparent version of that same core loop — useful for demonstrating you
understand the *problem space*, not just that you can call `.fit()` on a
model.

## Setup (all free)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate synthetic session logs
python generate_logs.py

# 3. Run anomaly detection
python detect_anomalies.py

# 4. Get a free Groq API key: https://console.groq.com/keys
export GROQ_API_KEY="your_key_here"     # Windows: set GROQ_API_KEY=your_key_here

# 5. Generate AI triage notes for flagged sessions
python ai_triage.py

# 6. Launch the dashboard
streamlit run dashboard.py
```

## Project files

| File | Purpose |
|---|---|
| `generate_logs.py` | Creates synthetic privileged session logs with planted anomalies for validation |
| `detect_anomalies.py` | Feature engineering + Isolation Forest anomaly scoring |
| `ai_triage.py` | Sends flagged sessions to Groq LLM for plain-English + MITRE-mapped triage notes |
| `dashboard.py` | Streamlit UI to visualize and drill into results |

## Results on synthetic data

On the generated test set (500 normal sessions + 25 planted attack-like
sessions), the model caught **25/25 planted anomalies** with only 2 false
positives out of 525 total sessions. This is a synthetic-data sanity check,
not a real-world performance claim (see "Limitations" below).

## The 6 features used (and why)

| Feature | Why it signals risk |
|---|---|
| Off-hours access | Legitimate admin work usually happens during business hours |
| Unusual source location | Deviating from a user's typical login geography can indicate credential theft |
| Privilege escalation count | Repeated escalations in one session is a common attacker pattern |
| Session duration | Abnormally long sessions can indicate data exfiltration or lateral movement |
| Command volume | Unusually high activity volume vs. that user's norm |
| Resource sensitivity | Access to high-value systems (domain controller, prod DB) carries more inherent risk |

## How to explain this in an interview (short version)

> "I built a system that watches privileged sessions — like an admin
> logging into a server — and learns what normal looks like for each
> user. When behavior looks different, like logging in at 3am from a new
> country or escalating privileges repeatedly, it gets flagged. An AI
> layer then reads the flagged session and writes a plain-English
> explanation of why it's risky, mapped to a MITRE ATT&CK technique, so
> a SOC analyst can triage it faster instead of digging through raw logs."

## Honest limitations (be ready to say this if asked)

- **Synthetic data, not real attack data.** This is a proof-of-concept
  demonstrating the anomaly detection + AI triage *approach*, not a
  validated production system.
- **No ground truth in the real world.** Unsupervised models like this
  have no way to be "graded" the way a supervised classifier can be —
  validation relies on manual review of flagged cases and tuning the
  `contamination` parameter (the assumed % of anomalous sessions) to your
  environment.
- **Behavior drift.** A user's "normal" legitimately changes over time
  (e.g., a promotion, a new project) — a production system would need
  a rolling baseline rather than a static one.
- **Would need integration with real session recording/keystroke logging**
  for full parity with commercial PAM tools — this project works off
  session metadata, not full session content.

## Tech stack

Python, pandas, scikit-learn (Isolation Forest), Faker (synthetic data),
Groq API (free tier, Llama 3.3 70B) for AI triage, Streamlit + Plotly for
the dashboard. No paid services required.
