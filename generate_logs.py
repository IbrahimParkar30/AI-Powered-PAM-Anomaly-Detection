"""
generate_logs.py
-----------------
Generates synthetic privileged-access session logs to simulate what a
PAM (Privileged Access Management) system like Arcon/CyberArk would record.

Each row = one privileged session (an admin/root/service-account login).

We deliberately plant a handful of "attack-like" sessions (off-hours,
impossible travel, unusual resource access, privilege escalation) so we
have something for the anomaly detector to actually catch. In the real
world you would NOT have these labels - this script keeps them internally
just so YOU can verify the model is working, not for the model to use.
"""

import random
import pandas as pd
from datetime import datetime, timedelta
from faker import Faker

fake = Faker()
random.seed(42)

USERS = ["admin_raj", "svc_backup", "admin_priya", "root_db01",
         "admin_karan", "svc_deploy", "admin_neha", "sysadmin_vik"]

# Each user has a "home" city/country - used to detect impossible travel
USER_HOME_LOCATION = {u: (fake.city(), fake.country()) for u in USERS}

RESOURCES = ["prod-db-01", "prod-db-02", "hr-fileserver", "finance-erp",
             "backup-vault", "domain-controller", "customer-crm", "billing-api"]

SENSITIVE_RESOURCES = {"prod-db-01", "domain-controller", "finance-erp", "billing-api"}

N_NORMAL_SESSIONS = 500
N_ANOMALOUS_SESSIONS = 25


def random_business_hours_timestamp(days_back=30):
    day = datetime.now() - timedelta(days=random.randint(0, days_back))
    hour = random.randint(8, 19)  # normal working hours
    minute = random.randint(0, 59)
    return day.replace(hour=hour, minute=minute, second=0, microsecond=0)


def random_off_hours_timestamp(days_back=30):
    day = datetime.now() - timedelta(days=random.randint(0, days_back))
    hour = random.choice(list(range(0, 5)) + list(range(23, 24)))  # 11pm-5am
    minute = random.randint(0, 59)
    return day.replace(hour=hour, minute=minute, second=0, microsecond=0)


def make_session(user, timestamp, city, country, resource,
                  duration_min, commands_run, privilege_escalations,
                  is_planted_anomaly=False, anomaly_reason=""):
    return {
        "session_id": fake.uuid4()[:8],
        "user": user,
        "timestamp": timestamp,
        "source_city": city,
        "source_country": country,
        "resource_accessed": resource,
        "resource_sensitivity": "high" if resource in SENSITIVE_RESOURCES else "normal",
        "session_duration_min": duration_min,
        "commands_run": commands_run,
        "privilege_escalations": privilege_escalations,
        "_ground_truth_anomaly": is_planted_anomaly,   # for our own validation only
        "_ground_truth_reason": anomaly_reason,         # NOT used by the model
    }


def generate_normal_sessions():
    rows = []
    for _ in range(N_NORMAL_SESSIONS):
        user = random.choice(USERS)
        city, country = USER_HOME_LOCATION[user]
        ts = random_business_hours_timestamp()
        resource = random.choice(RESOURCES)
        duration = max(2, int(random.gauss(20, 8)))
        commands = max(1, int(random.gauss(15, 5)))
        escalations = random.choice([0, 0, 0, 1])  # rarely escalate, and that's normal-ish
        rows.append(make_session(user, ts, city, country, resource,
                                  duration, commands, escalations))
    return rows


def generate_anomalous_sessions():
    rows = []
    scenarios = [
        "off_hours_access",
        "impossible_travel",
        "privilege_escalation_spike",
        "sensitive_resource_first_time",
        "abnormally_long_session",
    ]
    for i in range(N_ANOMALOUS_SESSIONS):
        user = random.choice(USERS)
        home_city, home_country = USER_HOME_LOCATION[user]
        scenario = scenarios[i % len(scenarios)]

        if scenario == "off_hours_access":
            ts = random_off_hours_timestamp()
            city, country = home_city, home_country
            resource = random.choice(RESOURCES)
            duration = max(2, int(random.gauss(20, 8)))
            commands = max(1, int(random.gauss(15, 5)))
            escalations = 0

        elif scenario == "impossible_travel":
            ts = random_business_hours_timestamp()
            city, country = fake.city(), random.choice(
                ["Russia", "North Korea", "Nigeria", "Belarus"])
            resource = random.choice(RESOURCES)
            duration = max(2, int(random.gauss(20, 8)))
            commands = max(1, int(random.gauss(15, 5)))
            escalations = 0

        elif scenario == "privilege_escalation_spike":
            ts = random_business_hours_timestamp()
            city, country = home_city, home_country
            resource = random.choice(list(SENSITIVE_RESOURCES))
            duration = max(2, int(random.gauss(20, 8)))
            commands = max(1, int(random.gauss(15, 5)))
            escalations = random.randint(5, 9)  # way above normal

        elif scenario == "sensitive_resource_first_time":
            ts = random_business_hours_timestamp()
            city, country = home_city, home_country
            resource = "domain-controller"
            duration = int(random.gauss(45, 10))
            commands = int(random.gauss(60, 10))  # heavy activity
            escalations = random.randint(2, 4)

        else:  # abnormally_long_session
            ts = random_business_hours_timestamp()
            city, country = home_city, home_country
            resource = random.choice(RESOURCES)
            duration = random.randint(180, 300)  # 3-5 hours, way above normal
            commands = random.randint(100, 200)
            escalations = random.randint(1, 3)

        rows.append(make_session(user, ts, city, country, resource,
                                  duration, commands, escalations,
                                  is_planted_anomaly=True, anomaly_reason=scenario))
    return rows


def main():
    rows = generate_normal_sessions() + generate_anomalous_sessions()
    df = pd.DataFrame(rows)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle
    df.to_csv("privileged_access_logs.csv", index=False)
    print(f"Generated {len(df)} sessions "
          f"({N_NORMAL_SESSIONS} normal, {N_ANOMALOUS_SESSIONS} planted anomalies)")
    print("Saved to privileged_access_logs.csv")


if __name__ == "__main__":
    main()
