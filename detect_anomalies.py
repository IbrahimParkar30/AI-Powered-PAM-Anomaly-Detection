"""
detect_anomalies.py
--------------------
Turns raw session logs into numeric "risk signals" (feature engineering),
then runs Isolation Forest to flag sessions that look statistically unusual.

PLAIN-ENGLISH EXPLANATION (use this when someone asks how it works):
    1. For every user, we build a "normal profile": their usual login hours,
       their usual location, their usual number of commands/escalations.
    2. For every session, we measure HOW FAR it deviates from that user's
       normal profile (a few numbers per session - the "features").
    3. Isolation Forest looks at all sessions' feature values and learns
       what the "normal cluster" of behavior looks like. Anything that
       sits far outside that cluster gets an anomaly score.
    4. We don't tell the model what an "attack" looks like - it never sees
       labels. It only learns "normal" and flags what's different. That's
       why it's called "unsupervised" - useful because in the real world
       you rarely have labeled examples of insider threats/PAM abuse.

You do NOT need to understand the Isolation Forest math. All you're
using is: model.fit(features) -> model.predict(features).
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["hour"] = df["timestamp"].dt.hour

    # Feature 1: off-hours flag (before 6am or after 10pm)
    df["is_off_hours"] = ((df["hour"] < 6) | (df["hour"] >= 22)).astype(int)

    # Feature 2: is this the user's usual home country? (proxy for impossible travel)
    user_home_country = df.groupby("user")["source_country"].agg(
        lambda x: x.value_counts().idxmax())
    df["home_country"] = df["user"].map(user_home_country)
    df["is_unusual_location"] = (df["source_country"] != df["home_country"]).astype(int)

    # Feature 3: privilege escalations (raw count - higher = riskier)
    df["privilege_escalations"] = df["privilege_escalations"]

    # Feature 4: session duration (raw minutes - unusually long sessions stand out)
    df["session_duration_min"] = df["session_duration_min"]

    # Feature 5: command volume (raw count)
    df["commands_run"] = df["commands_run"]

    # Feature 6: sensitive resource flag
    df["is_sensitive_resource"] = (df["resource_sensitivity"] == "high").astype(int)

    feature_cols = [
        "is_off_hours",
        "is_unusual_location",
        "privilege_escalations",
        "session_duration_min",
        "commands_run",
        "is_sensitive_resource",
    ]
    return df, feature_cols


def run_detection(input_csv="privileged_access_logs.csv",
                   output_csv="flagged_sessions.csv",
                   contamination=0.05):
    df = pd.read_csv(input_csv)
    df, feature_cols = engineer_features(df)

    X = df[feature_cols].values

    # contamination = the % of sessions we EXPECT to be anomalous.
    # 0.05 means "assume roughly 5% of sessions look unusual" - tune this
    # based on your environment; it's the one "dial" you control.
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
    )
    model.fit(X)

    df["anomaly_score"] = model.decision_function(X)   # higher = more normal
    df["is_anomaly"] = model.predict(X) == -1           # True if flagged

    # Convert score to an intuitive 0-100 "risk score" (higher = riskier)
    min_s, max_s = df["anomaly_score"].min(), df["anomaly_score"].max()
    df["risk_score"] = (100 * (max_s - df["anomaly_score"]) / (max_s - min_s)).round(1)

    flagged = df[df["is_anomaly"]].sort_values("risk_score", ascending=False)
    flagged.to_csv(output_csv, index=False)

    # Quick validation against our planted ground truth (for YOUR eyes only -
    # a real deployment wouldn't have this, since real attacks aren't labeled)
    if "_ground_truth_anomaly" in df.columns:
        caught = df[df["_ground_truth_anomaly"] & df["is_anomaly"]].shape[0]
        total_planted = df["_ground_truth_anomaly"].sum()
        print(f"Flagged {len(flagged)} sessions out of {len(df)} total.")
        print(f"Caught {caught}/{total_planted} planted anomalies "
              f"({100*caught/total_planted:.0f}% recall on synthetic attacks).")

    df.to_csv("all_sessions_scored.csv", index=False)
    print(f"Saved flagged sessions to {output_csv}")
    return flagged


if __name__ == "__main__":
    run_detection()
