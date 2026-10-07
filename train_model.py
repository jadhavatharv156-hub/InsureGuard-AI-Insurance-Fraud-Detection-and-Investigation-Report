import os
import pickle
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
    precision_score,
    recall_score,
    f1_score
)
from xgboost import XGBClassifier


# ============================================================
# CONFIGURATION & PATHS
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(BASE_DIR, "fraud_oracle.csv")
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")
ENCODERS_PATH = os.path.join(BASE_DIR, "encoders.pkl")


# ============================================================
# TRAIN AND EXPORT FUNCTION
# ============================================================
def train_and_export():
    print("Loading dataset...")

    if not os.path.exists(CSV_PATH):
        raise FileNotFoundError(f"Dataset not found at: {CSV_PATH}")

    df = pd.read_csv(CSV_PATH)
    print(f"Dataset shape: {df.shape}")

    # Explicit list of features matching app.py
    features = [
        "Month", "WeekOfMonth", "DayOfWeek", "Make", "AccidentArea", "Sex",
        "MaritalStatus", "Age", "Fault", "PolicyType", "VehicleCategory",
        "VehiclePrice", "Deductible", "DriverRating", "Days_Policy_Accident",
        "Days_Policy_Claim", "PastNumberOfClaims", "AgeOfVehicle",
        "PoliceReportFiled", "WitnessPresent"
    ]
    target_column = "FraudFound_P"

    if target_column not in df.columns:
        raise ValueError(f"Target column '{target_column}' not found in dataset.")

    X = df[features].copy()
    y = df[target_column].astype(int)

    print("\nTarget distribution:")
    print(y.value_counts().rename({0: "Legitimate", 1: "Fraud"}))

    # ========================================================
    # ENCODE ALL NON-NUMERIC COLUMNS (Fixes KeyError: 'str')
    # ========================================================
    encoders = {}
    for col in X.columns:
        if not pd.api.types.is_numeric_dtype(X[col]):
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col].astype(str))
            encoders[col] = le
        else:
            # Ensure numeric columns are cleanly cast to standard numerical types
            X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)

    # ========================================================
    # TRAIN / TEST SPLIT
    # ========================================================
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    negative_count = (y_train == 0).sum()
    positive_count = (y_train == 1).sum()
    scale_pos_weight = negative_count / positive_count

    print(f"\nTraining samples: {len(X_train)} | Testing samples: {len(X_test)}")
    print(f"Scale Pos Weight Ratio: {scale_pos_weight:.2f}")

    # ========================================================
    # BUILD & TRAIN XGBOOST MODEL
    # ========================================================
    model = XGBClassifier(
        n_estimators=300,
        max_depth=4,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos_weight,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1
    )

    print("\nTraining XGBoost model...")
    model.fit(X_train, y_train)

    # ========================================================
    # EVALUATION
    # ========================================================
    y_pred = model.predict(X_test)
    y_probability = model.predict_proba(X_test)[:, 1]

    accuracy = accuracy_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_probability)
    cm = confusion_matrix(y_test, y_pred)

    print("\n==============================")
    print("       MODEL RESULTS")
    print("==============================")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"ROC-AUC:  {roc_auc:.4f}")

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Fraud"], zero_division=0))

    print("\nConfusion Matrix:")
    print("                 Predicted")
    print("                 Legitimate   Fraud")
    print(f"Actual Legitimate    {cm[0][0]:5d}      {cm[0][1]:5d}")
    print(f"Actual Fraud         {cm[1][0]:5d}      {cm[1][1]:5d}")

    fraud_precision = precision_score(y_test, y_pred, zero_division=0)
    fraud_recall = recall_score(y_test, y_pred, zero_division=0)
    fraud_f1 = f1_score(y_test, y_pred, zero_division=0)

    print("\n==============================")
    print("      FRAUD DETECTION")
    print("==============================")
    print(f"Fraud Precision: {fraud_precision:.4f}")
    print(f"Fraud Recall:    {fraud_recall:.4f}")
    print(f"Fraud F1-Score:  {fraud_f1:.4f}")

    # ========================================================
    # SAVE ARTIFACTS FOR FLASK APP
    # ========================================================
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)

    with open(ENCODERS_PATH, "wb") as f:
        pickle.dump(encoders, f)

    print("\n==============================")
    print(" MODEL & ENCODERS SAVED SUCCESSFULLY")
    print("==============================")
    print(f"Saved Model:    {MODEL_PATH}")
    print(f"Saved Encoders: {ENCODERS_PATH}")


if __name__ == "__main__":
    train_and_export()