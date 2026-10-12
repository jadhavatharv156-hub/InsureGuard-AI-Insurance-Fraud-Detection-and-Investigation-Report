# 🛡️ InsureGuard – AI Insurance Fraud Detection & Investigation

InsureGuard is a Flask web application that scores insurance claims for fraud risk, explains *why* a claim was flagged, and gives investigators a workflow to review, approve or reject cases. It combines an XGBoost model trained on the public `fraud_oracle` auto-insurance dataset with a rule-based risk engine, image forensics and a claim-network graph.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Flask](https://img.shields.io/badge/flask-web%20app-lightgrey)
![XGBoost](https://img.shields.io/badge/model-XGBoost-orange)
![MySQL](https://img.shields.io/badge/database-MySQL-blue)

## 📖 Overview

Insurance fraud is expensive and hard to spot manually. InsureGuard helps by:

- Giving every submitted claim an explainable **risk score (0–99%)**
- Flagging suspicious evidence (duplicate or scrubbed images)
- Linking claims that share phone numbers or repair shops
- Letting admins **investigate**, update case status, and export a **PDF report**

## ✨ Features

- **Role-based access** – customers file and track claims; admins manage users and cases
- **Explainable risk engine** – each score comes with a list of risk factors and their impact (e.g. "Rapid claim after policy inception +25%")
- **Forensic checks on uploaded evidence**
  - SHA-256 hashing to detect duplicate images across claims
  - EXIF analysis to flag screenshots or images with missing capture timestamps
- **Syndicate detection** – flags phone numbers shared across accounts and repair shops tied to multiple fraud flags
- **Network graph view** – interactive graph of users, claims, phones and repair shops (admin only)
- **Case management workflow** – `ASSESSED → PENDING_REVIEW → UNDER_INVESTIGATION → APPROVED / REJECTED`, with investigator notes and an audit trail
- **PDF risk reports** – downloadable per-claim assessment generated with ReportLab
- **ML training pipeline** – XGBoost classifier with class-imbalance handling (`scale_pos_weight`)

## 🧰 Tech Stack

| Layer      | Technology                                           |
|------------|------------------------------------------------------|
| Backend    | Python, Flask, Flask-SQLAlchemy                      |
| Database   | MySQL (via PyMySQL)                                  |
| ML         | XGBoost, scikit-learn, pandas, NumPy, SHAP           |
| Forensics  | Pillow (EXIF), hashlib (SHA-256)                     |
| Reports    | ReportLab                                            |
| Frontend   | Jinja2 templates, HTML/CSS/JS                        |

## 📁 Project Structure

```
InsureGuard/
├── app.py                  # Flask app: routes, DB models, risk engine
├── risk_engine.py          # Standalone rule-based claim risk scoring
├── train_model.py          # Trains the XGBoost model and saves artifacts
├── fix_db.py               # Helper script to widen the users.password column
├── config.py
├── fraud_oracle.csv        # Training dataset
├── model.pkl               # Trained XGBoost model
├── encoders.pkl            # Label encoders for categorical features
├── feature_options.json    # Allowed values for model input features
├── ml model/
│   └── InsureGuard_ML.ipynb  # Exploration / experiments notebook
├── models/                 # Additional saved model(s)
├── templates/              # HTML pages (login, dashboard, predict, admin, network graph…)
├── static/                 # CSS and JavaScript
└── requirements.txt
```

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- MySQL server running locally (or any MySQL-compatible host)

### 1. Clone and install

```bash
git clone https://github.com/jadhavatharv156-hub/InsureGuard-AI-Insurance-Fraud-Detection-and-Investigation-Report.git
cd InsureGuard-AI-Insurance-Fraud-Detection-and-Investigation-Report

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install pillow              # used for EXIF forensics
```

### 2. Create the database

```sql
CREATE DATABASE insureguard_db;
```

### 3. Configure environment variables

| Variable         | Description                         | Default            |
|------------------|-------------------------------------|--------------------|
| `SECRET_KEY`     | Flask session secret                | *(set your own)*   |
| `DATABASE_URL`   | Full SQLAlchemy connection string   | built from below   |
| `MYSQL_USER`     | MySQL username                      | `root`             |
| `MYSQL_PASSWORD` | MySQL password                      | *(set your own)*   |
| `MYSQL_HOST`     | MySQL host                          | `localhost`        |
| `MYSQL_DB`       | Database name                       | `insureguard_db`   |

Example:

```bash
export SECRET_KEY="change-me"
export DATABASE_URL="mysql+pymysql://root:<your-password>@localhost:3306/insureguard_db"
```

### 4. (Optional) Retrain the model

```bash
python train_model.py
```

This reads `fraud_oracle.csv`, trains the XGBoost model, prints accuracy, ROC-AUC, precision/recall/F1 and the confusion matrix, then saves `model.pkl` and `encoders.pkl`.

### 5. Run the app

```bash
python app.py
```

Open **http://localhost:5000**. Tables are created automatically on first run, along with a default admin account (see Security notes below).

## 💡 How It Works

1. A customer submits a claim (amount, severity, policy type, authorities contacted, contact phone, repair shop, optional evidence image).
2. The risk engine adds up weighted signals: claim value, severity, policy age, unreported incidents, duplicate files, EXIF anomalies, shared phone/repair-shop links and weather mismatches.
3. Scores of **50% or higher** are flagged as potential fraud and sent for review.
4. Admins open the case, add investigator notes, change its status, explore the network graph, and download the PDF report.

## 🔒 Security Notes

Before deploying anywhere public:

- Set your own `SECRET_KEY`; do not rely on the fallback in `app.py`
- Change the default admin password created on first run
- Make sure no database passwords are hard-coded in `app.py`; use environment variables only
- Turn off `debug=True` in production
- Add `database.db`, `__pycache__/` and `uploads/` to `.gitignore`

## 🗺️ Roadmap

- [ ] Use SHAP explanations directly in the claim view
- [ ] Wire the trained XGBoost model into the live claim-scoring flow
- [ ] Real weather and geolocation verification API
- [ ] Docker setup
- [ ] Unit tests

## 🤝 Contributing

1. Fork the repo
2. Create a branch: `git checkout -b feature/your-feature`
3. Commit: `git commit -m "Add your feature"`
4. Push: `git push origin feature/your-feature`
5. Open a Pull Request


## 👤 Author

**Atharv Jadhav** – [GitHub](https://github.com/jadhavatharv156-hub)

## 🙏 Acknowledgements

- Dataset: `fraud_oracle.csv` (public vehicle insurance fraud dataset)
