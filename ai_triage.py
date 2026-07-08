"""
ai_triage.py
------------
Takes the flagged (anomalous) sessions from detect_anomalies.py and asks
an LLM (via Groq's free API) to write a SOC-analyst-style triage note for
each one: plain-English explanation + likely MITRE ATT&CK technique.

This is the layer that turns "a number said this is weird" into
"here's what a human analyst would actually write in a ticket" -
that's the AI-integration piece that makes this more than a plain
ML anomaly detector.

SETUP:
    1. Get a free API key: https://console.groq.com/keys
    2. Set it as an environment variable before running:
         export GROQ_API_KEY="your_key_here"       (Mac/Linux)
         set GROQ_API_KEY=your_key_here             (Windows cmd)
    3. Run: python ai_triage.py
"""

import os
import json
import pandas as pd
from groq import Groq

MODEL = "llama-3.3-70b-versatile"  # Groq's free-tier model

SYSTEM_PROMPT = """You are a SOC (Security Operations Center) L1 analyst assistant \
specializing in Privileged Access Management (PAM) incident triage. \
For each flagged privileged-session anomaly, write:
1. A 2-3 sentence plain-English explanation of why this session looks risky.
2. The single most likely MITRE ATT&CK technique ID + name it relates to.
3. A recommended next action (e.g., "verify with user", "escalate to L2", "isolate account").

Respond ONLY in valid JSON with keys: "explanation", "mitre_technique", "recommended_action". \
No markdown, no extra text."""


def build_user_prompt(row) -> str:
    return f"""Flagged privileged session details:
- User: {row['user']}
- Timestamp: {row['timestamp']}
- Source location: {row['source_city']}, {row['source_country']} (user's usual country: {row['home_country']})
- Resource accessed: {row['resource_accessed']} (sensitivity: {row['resource_sensitivity']})
- Session duration: {row['session_duration_min']} minutes
- Commands run: {row['commands_run']}
- Privilege escalations during session: {row['privilege_escalations']}
- Off-hours access: {'Yes' if row['is_off_hours'] else 'No'}
- Unusual location for this user: {'Yes' if row['is_unusual_location'] else 'No'}
- Computed risk score: {row['risk_score']}/100
"""


def get_triage_note(client, row):
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_prompt(row)},
            ],
            temperature=0.3,
            max_tokens=300,
        )
        content = response.choices[0].message.content.strip()
        content = content.replace("```json", "").replace("```", "").strip()
        parsed = json.loads(content)
        return parsed
    except Exception as e:
        return {
            "explanation": f"[LLM call failed: {e}]",
            "mitre_technique": "N/A",
            "recommended_action": "Manual review required",
        }


def main():
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        print("ERROR: GROQ_API_KEY environment variable not set.")
        print("Get a free key at https://console.groq.com/keys and run:")
        print('  export GROQ_API_KEY="your_key_here"')
        return

    client = Groq(api_key=api_key)
    df = pd.read_csv("flagged_sessions.csv")

    results = []
    for i, row in df.iterrows():
        print(f"Triaging session {i+1}/{len(df)}: {row['session_id']} ({row['user']})...")
        note = get_triage_note(client, row)
        results.append(note)

    triage_df = pd.DataFrame(results)
    final_df = pd.concat([df.reset_index(drop=True), triage_df], axis=1)
    final_df.to_csv("triaged_sessions.csv", index=False)
    print(f"\nDone. Saved AI-triaged sessions to triaged_sessions.csv")


if __name__ == "__main__":
    main()
