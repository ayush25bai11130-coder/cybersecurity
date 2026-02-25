# 🛡️ CyberShield — URL Security Analyzer  

CyberShield is a hybrid URL security analyzer that combines rule-based heuristics and machine learning to detect potentially malicious URLs.

The system evaluates URLs across 12 security-relevant features and outputs:

- Risk Score (Rule-based percentage)
- Malicious Probability (ML prediction)
- Human-readable threat explanation

Designed to be fast, explainable, and lightweight, CyberShield can be used for educational purposes and real-world cybersecurity screening.

---

## 🚨 Problem Statement

Phishing and malicious URLs are among the most common cybersecurity threats today. Many existing solutions are either black-box ML systems or too complex for non-technical users.

CyberShield addresses this by providing:
- Transparent rule-based scoring
- Machine learning validation
- Fast processing (sub-50ms)
- Clear threat explanations

---

## 🧠 Hybrid Detection Architecture

CyberShield combines two approaches:

### 1️⃣ Rule-Based Scoring Engine
Assigns weighted risk points based on suspicious indicators such as:
- No HTTPS
- IP-based URLs
- Suspicious TLDs
- Phishing keywords
- Excessive subdomains
- High URL entropy

The final rule score is capped at 100%.

### 2️⃣ Machine Learning Model
- Algorithm: Random Forest Classifier (scikit-learn)
- Input: 12 extracted URL features
- Output: Malicious probability (0–100%)

The ML model helps detect patterns beyond predefined rules.

---

## 🔎 Feature Extraction (12 Features)

- URL Length  
- Dot Count  
- HTTPS Presence  
- IP-Based Hostname  
- '@' Symbol Detection  
- Double Slash Misuse  
- Suspicious TLD  
- Phishing Keywords  
- Hyphen Count  
- Subdomain Depth  
- Special Character Count  
- Shannon Entropy  

---

## 🛠️ Technology Stack

- Backend: Python + Flask  
- Machine Learning: scikit-learn (Random Forest)  
- Frontend: HTML5, CSS3, JavaScript  
- Data Processing: Pandas, NumPy  
- Feature Extraction: urllib, regex  

---

## 🔄 System Workflow

1. User submits a URL  
2. Backend extracts features  
3. Rule engine calculates risk score  
4. ML model predicts malicious probability  
5. Results returned as JSON  
6. Frontend displays risk analysis  

---

## 📡 API Endpoint

POST /analyze

Request:
{
  "url": "http://example.com"
}

Response:
{
  "score": 75,
  "mal_prob": 0.82,
  "threats": ["No HTTPS", "Suspicious TLD"]
}

---

## 🚀 Future Enhancements

- WHOIS domain age lookup  
- VirusTotal API integration  
- Larger phishing datasets  
- Browser extension version  
- Model retraining with user feedback  

---

## 🎯 Key Advantages

- Hybrid rule-based + ML detection  
- High explainability  
- Fast processing  
- Scalable Flask backend  

---

CyberShield | Cyber Carnival Project | Version 1.0
