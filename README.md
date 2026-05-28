# 🛡 APT Shield — Advanced Persistent Threat Detection System

A real-time network security system that detects APT attacks using **Random Forest ML**, 
live packet capture, and the **MITRE ATT&CK framework**.

## 👥 Team
- Adam Rajasthanwala (EN23CS301054)
- Abhishek Rathore (EN23CS301051)

**Guide:** Prof. Ashish Kumar Kumawat  
**Institution:** Medicaps University, Indore

---

## ✨ Features
- 🧠 Random Forest classifier — 100% accuracy across 5 threat classes
- 📡 Live packet capture via Scapy (simulation fallback for Windows)
- 🌐 GeoIP world map with animated attack arcs
- 👥 Role-based access (Admin vs User)
- 🎯 MITRE ATT&CK framework mapping (T1046, T1078, T1021, T1041)
- 📧 Gmail email alerts for critical threats
- ⚡ Real-time WebSocket dashboard

## 🔍 Threat Classes Detected
| Label | Class | MITRE |
|-------|-------|-------|
| 0 | Normal Traffic | — |
| 1 | Reconnaissance | T1046 |
| 2 | Initial Compromise | T1078 |
| 3 | Lateral Movement | T1021 |
| 4 | Data Exfiltration | T1041 |

## 🚀 Quick Start
```bash
pip install flask flask-socketio eventlet scikit-learn pandas numpy scapy
python app.py
# Open http://127.0.0.1:5000
# Login: admin / apt@1234
```

## 🛠 Tech Stack
Python · Flask · scikit-learn · SQLite · Scapy · Socket.IO · HTML/CSS/JS

## 📊 Model Performance
- Accuracy: **100%**  · Precision: **1.00**  · Recall: **1.00**  · F1: **1.00**
- Training samples: 5,000  · Test samples: 1,000  · Training time: < 2 seconds
