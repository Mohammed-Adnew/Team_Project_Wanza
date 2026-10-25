# 🛡️ WanzaGuard (Team Project Wanza)

> Cloud-native phishing detection and INSA compliance verification platform.

---

## 👥 Team Members

| Full Name | Student ID |
| :--- | :--- |
| **Yabets Solomon** | CTC-660-26 |
| **Mohammed Adnew Hussein** | CTC-3318-26 |
| **Anwar Hussen** | CTC-4395-26 |
| **Kalkidan Khnet** | CTC-3784-26 |
| **Victoria Solomon** | CTC-2492-26 |
| **Kety Seyoum** | CTC-4325-26 |

---

## 🔗 Quick Access (Live System)

Click below to test the live, running deployment directly in your browser:

- 🚀 **[Launch Analyst Dashboard (Primary Portal)](https://frontendanalyst.vercel.app)** — Incident triage & INSA readiness view.
- 📨 **[Launch Employee Reporting Portal](https://wanzaemployee.vercel.app)** — End-user suspicious email submission.
- 🎥 **[Watch Full Demonstration Video (Google Drive)](https://drive.google.com/file/d/15-PsAp0z_A6Fbehfo1H--yeWgjWuxqz8/view?usp=drivesdk)**

---

## 📌 Project Overview

WanzaGuard automates enterprise email threat response and regulatory compliance tracking:
- **Phishing Triage:** Ingests email streams via webhooks and parses authentication headers (SPF, DKIM, DMARC).
- **Threat Scoring:** Queries domain and URL reputation via security intelligence APIs.
- **Regulatory Tracking:** Maps security findings directly to the 18 statutory duties under **Article 7 of INSA Proclamation No. 1426/2026**.

---

## 🏗️ Architecture & Deployment

- **Backend:** Flask REST API deployed on **Render** (`team-project-wanza.onrender.com`)
- **Frontends:** Dual React portals deployed on **Vercel** (`frontendanalyst` & `wanzaemployee`)
- **Database:** PostgreSQL cloud database
---

## 🛠️ Developer Setup (Local Run)

*For development and local testing only:*

```bash
git clone [https://github.com/Mohammed-Adnew/Team_Project_Wanza.git](https://github.com/Mohammed-Adnew/Team_Project_Wanza.git)
cd Team_Project_Wanza
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
flask run
```
