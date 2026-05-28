"""
ml/model.py
Random Forest APT Detection Model
- Generates synthetic dataset
- Trains & evaluates the model
- Saves/loads model with pickle
- Provides predict() for real-time use
"""

import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'rf_apt_model.pkl')

FEATURES = [
    'duration', 'packet_count', 'byte_count', 'failed_logins',
    'unique_ports', 'dns_requests', 'outbound_connections',
    'data_exfil_bytes', 'privilege_escalation', 'lateral_movement',
    'c2_beacon_interval', 'encrypted_traffic_ratio'
]

CLASS_NAMES = {
    0: 'Normal Traffic',
    1: 'Reconnaissance',
    2: 'Initial Compromise',
    3: 'Lateral Movement',
    4: 'Data Exfiltration'
}

MITRE_MAP = {
    0: None,
    1: 'T1046 - Network Service Discovery',
    2: 'T1078 - Valid Accounts / T1548 - Privilege Abuse',
    3: 'T1021 - Remote Services / T1563 - Remote Service Hijacking',
    4: 'T1041 - Exfiltration Over C2 / T1071 - App Layer Protocol'
}


# ── Dataset Generation ────────────────────────────────────────────────────────

def generate_dataset(n_samples: int = 5000) -> pd.DataFrame:
    np.random.seed(42)
    rows = []

    def add(n, label, overrides):
        base = dict(
            duration=0, packet_count=0, byte_count=0,
            failed_logins=0, unique_ports=0, dns_requests=0,
            outbound_connections=0, data_exfil_bytes=0,
            privilege_escalation=0, lateral_movement=0,
            c2_beacon_interval=0, encrypted_traffic_ratio=0.0,
            label=label
        )
        base.update(overrides)
        for _ in range(n):
            row = {}
            for k, v in base.items():
                if isinstance(v, tuple):
                    if isinstance(v[0], float) or isinstance(v[1], float):
                        row[k] = round(np.random.uniform(v[0], v[1]), 4)
                    else:
                        row[k] = int(np.random.randint(v[0], v[1]+1))
                else:
                    row[k] = v
            rows.append(row)

    half = n_samples // 2
    quarter = n_samples // 8

    # Normal (50%)
    add(half, 0, dict(
        duration=(0.1, 5.0), packet_count=(1, 50), byte_count=(100, 5000),
        failed_logins=(0, 2), unique_ports=(1, 5), dns_requests=(1, 20),
        outbound_connections=(1, 10), data_exfil_bytes=(0, 500),
        encrypted_traffic_ratio=(0.1, 0.5)
    ))
    # Reconnaissance (12.5%)
    add(quarter, 1, dict(
        duration=(0.01, 1.0), packet_count=(100, 500), byte_count=(50, 500),
        unique_ports=(50, 200), dns_requests=(50, 200),
        outbound_connections=(20, 100), encrypted_traffic_ratio=(0.0, 0.2)
    ))
    # Initial Compromise (12.5%)
    add(quarter, 2, dict(
        duration=(1.0, 10.0), packet_count=(200, 1000), byte_count=(5000, 50000),
        failed_logins=(5, 20), privilege_escalation=(0, 2),
        encrypted_traffic_ratio=(0.3, 0.7)
    ))
    # Lateral Movement (12.5%)
    add(quarter, 3, dict(
        duration=(5.0, 50.0), packet_count=(500, 3000), byte_count=(10000, 100000),
        failed_logins=(2, 10), privilege_escalation=(1, 3),
        lateral_movement=(1, 5), c2_beacon_interval=(30, 300),
        outbound_connections=(10, 50), data_exfil_bytes=(100, 5000),
        encrypted_traffic_ratio=(0.5, 0.9)
    ))
    # Data Exfiltration (12.5%)
    add(quarter, 4, dict(
        duration=(10.0, 100.0), packet_count=(1000, 10000),
        byte_count=(100000, 1000000), data_exfil_bytes=(50000, 500000),
        privilege_escalation=(1, 4), lateral_movement=(1, 4),
        c2_beacon_interval=(60, 600), dns_requests=(20, 100),
        encrypted_traffic_ratio=(0.7, 1.0)
    ))

    return pd.DataFrame(rows)


# ── Train ─────────────────────────────────────────────────────────────────────

def train_model(save: bool = True) -> dict:
    print("[ML] Generating dataset...")
    df = generate_dataset()

    X = df[FEATURES]
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("[ML] Training Random Forest (100 trees)...")
    clf = RandomForestClassifier(
        n_estimators=100, max_depth=15,
        random_state=42, n_jobs=-1
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    rec  = recall_score(y_test, y_pred, average='weighted', zero_division=0)
    f1   = f1_score(y_test, y_pred, average='weighted', zero_division=0)

    print(f"[ML] Accuracy : {acc:.4f}")
    print(f"[ML] Precision: {prec:.4f}  Recall: {rec:.4f}  F1: {f1:.4f}")
    print(classification_report(y_test, y_pred,
                                 target_names=list(CLASS_NAMES.values())))

    if save:
        with open(MODEL_PATH, 'wb') as f:
            pickle.dump(clf, f)
        print(f"[ML] Model saved → {MODEL_PATH}")

    return {
        'accuracy': round(acc, 4),
        'precision': round(prec, 4),
        'recall': round(rec, 4),
        'f1_score': round(f1, 4),
        'n_estimators': 100,
        'n_samples': len(df),
        'model_file': MODEL_PATH,
        'feature_importances': dict(zip(FEATURES, clf.feature_importances_.tolist())),
        'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
        'class_names': CLASS_NAMES
    }


# ── Load & Predict ────────────────────────────────────────────────────────────

_model = None

def load_model():
    global _model
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            print("[ML] No saved model found — training now...")
            train_model()
        with open(MODEL_PATH, 'rb') as f:
            _model = pickle.load(f)
        print("[ML] Model loaded ✅")
    return _model


def predict(features: dict) -> dict:
    """
    features: dict with keys matching FEATURES list
    returns:  dict with prediction, confidence, class_name, mitre, probabilities
    """
    clf = load_model()
    row = pd.DataFrame([[features.get(f, 0) for f in FEATURES]], columns=FEATURES)

    label      = int(clf.predict(row)[0])
    probs      = clf.predict_proba(row)[0].tolist()
    confidence = round(float(max(probs)), 4)

    return {
        'predicted_label':  label,
        'predicted_class':  CLASS_NAMES[label],
        'confidence':        confidence,
        'is_threat':         int(label != 0),
        'mitre_technique':  MITRE_MAP[label],
        'probabilities':     {CLASS_NAMES[i]: round(p, 4) for i, p in enumerate(probs)}
    }


def get_feature_importances() -> dict:
    clf = load_model()
    return dict(sorted(
        zip(FEATURES, clf.feature_importances_.tolist()),
        key=lambda x: x[1], reverse=True
    ))


if __name__ == '__main__':
    metrics = train_model()
    print("\nFeature Importances:")
    for feat, imp in sorted(
        metrics['feature_importances'].items(), key=lambda x: x[1], reverse=True
    ):
        bar = '█' * int(imp * 100)
        print(f"  {feat:<30} {imp:.4f}  {bar}")
