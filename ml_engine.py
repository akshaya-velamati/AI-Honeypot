import sqlite3
import pandas as pd
from sklearn.ensemble import IsolationForest


def run_ml_detection():
    print("ML model executed")  # To confirm ML is running

    conn = sqlite3.connect("honeypot.db")
    df = pd.read_sql_query("SELECT * FROM logs", conn)

    # Need minimum data for ML to work properly
    if len(df) < 5:
        conn.close()
        return

    # -------- Feature Engineering --------
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.hour

    # Count total login attempts per IP
    df['login_count'] = df.groupby('ip')['ip'].transform('count')

    # Select features for ML model
    features = df[['login_count', 'threat_score', 'hour']]

    # Isolation Forest Model
    model = IsolationForest(
        contamination=0.15,
        random_state=42
    )

    model.fit(features)

    # Predict anomalies (-1 = anomaly, 1 = normal)
    df['anomaly'] = model.predict(features)

    # -------- Update Database Based on ML --------
    for _, row in df.iterrows():
        if row['anomaly'] == -1:
            print("ML detected anomaly for ID:", row['id'])
            conn.execute(
                "UPDATE logs SET suspicious = 1 WHERE id = ?",
                (row['id'],)
            )

    conn.commit()
    conn.close()