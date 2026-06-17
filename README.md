# SentinelAI - Data Access Anomaly Detection System

## Overview

SentinelAI is an AI-powered Insider Threat Detection and Data Access Monitoring platform developed for the PS4 Security Analytics Challenge.

The system analyzes enterprise data access logs, builds user behavior profiles, detects anomalous activities, identifies unauthorized access attempts, and generates explainable security alerts with risk-based prioritization.

The solution combines machine learning anomaly detection with business-aware security rules to reduce false positives while improving detection accuracy.

---

## Problem Statement

Organizations generate thousands of access events across databases, file shares, business intelligence systems, and cloud platforms.

Traditional monitoring systems often generate excessive alerts by flagging all off-hours activity, resulting in alert fatigue and missed threats.

The objective is to:

* Detect insider threats
* Identify unauthorized access
* Detect suspicious data exports
* Monitor privileged account misuse
* Provide explainable alerts for security analysts
* Align with GDPR, NIST, and SOX requirements

---

## Solution Architecture

Data Access Logs
↓
Data Preprocessing
↓
User Profile Enrichment
↓
Feature Engineering
↓
Isolation Forest Anomaly Detection
↓
Rule-Based Risk Engine
↓
Risk Scoring & Classification
↓
Explainable Alert Generation
↓
Streamlit Dashboard & Incident Reports

---

## Features

### User Behavior Profiling

Builds behavioral baselines using:

* Department
* Job Role
* Privilege Level
* Approved Systems Access
* Employment Tenure
* Historical Activity Context

### Anomaly Detection

Isolation Forest identifies unusual behaviors such as:

* Abnormal resource access
* Suspicious exports
* Unusual activity patterns
* Behavioral deviations

### Unauthorized Access Detection

Flags activities where users access resources outside their approved access profile.

Examples:

* Marketing user accessing Customer Vault
* Finance user accessing HR systems
* Non-admin users performing administrative operations

### Risk Scoring Engine

Risk scores are calculated using multiple factors:

| Factor                       | Impact |
| ---------------------------- | ------ |
| Resource Sensitivity         | High   |
| Administrative Actions       | High   |
| Export Operations            | High   |
| Off-Hours Activity           | Medium |
| Failed Access Attempts       | Medium |
| Unauthorized Resource Access | High   |
| Isolation Forest Anomaly     | High   |

Final Risk Score Range:

* Low
* Medium
* High
* Critical

### Context-Aware Detection

To reduce false positives, the system considers:

* Month-end business activity
* Employee tenure
* Normal work schedules
* Department-specific behavior
* Resource sensitivity

### Explainable AI Alerts

Every alert includes:

* Why the activity was flagged
* Risk factors involved
* Business impact
* Recommended actions

---

## Machine Learning Model

Algorithm:

Isolation Forest

Reason for Selection:

* Works well with unlabeled datasets
* Effective for anomaly detection
* Suitable for insider threat scenarios
* Handles high-dimensional behavioral data

Features Used:

* Resource sensitivity
* Time classification
* Privilege level
* Failed access indicators
* User inactivity indicators
* Behavioral deviations

---

## Dashboard

The Streamlit dashboard provides:

* Risk Distribution Overview
* Critical Alert Monitoring
* User Investigation View
* Top Risky Activities
* Incident Analysis
* Explainable Alert Details

### Dashboard Screenshots

Add screenshots here:

![Dashboard](screenshots/dashboard.png)

![Critical Alerts](screenshots/critical_alerts.png)

![Incident Report](screenshots/incident_report.png)

---

## Sample Detected Threats

Examples detected by SentinelAI:

### Unauthorized Customer Data Access

* Marketing employee accessed Customer_Vault
* Outside approved access profile
* Critical risk generated

### Administrative Privilege Abuse

* Non-admin user performed admin operation
* High-risk alert generated

### Suspicious Export Activity

* Large-scale export activity
* Sensitive resource involved
* Behavioral anomaly detected

### Off-Hours Sensitive Access

* Access to restricted systems during unusual hours
* Context-aware risk evaluation applied

---

## Regulatory Alignment

### GDPR Article 32

Supports:

* Unauthorized access monitoring
* Personal data protection
* Security event detection

### NIST IR-4

Supports:

* Incident detection
* Alert generation
* Investigation workflow

### SOX 302

Supports:

* Audit trail visibility
* Financial system monitoring
* Access control verification

---

## Technology Stack

* Python
* Pandas
* NumPy
* Scikit-Learn
* Isolation Forest
* Streamlit
* Matplotlib

---

## Project Structure

Data-Access-Anomaly-Detection/

├── app.py

├── notebooks/

├── reports/

├── screenshots/

├── requirements.txt

├── README.md

└── data/

---

## Installation

Clone Repository

git clone <repository-url>

Install Dependencies

pip install -r requirements.txt

Run Application

streamlit run app.py

---

## Future Enhancements

* Real-time streaming log ingestion
* SIEM integration
* Automated incident response
* Graph-based user behavior analysis
* Deep learning anomaly detection
* Threat intelligence enrichment

---

## Business Impact

SentinelAI helps organizations:

* Reduce insider threat risk
* Detect unauthorized access faster
* Improve audit readiness
* Reduce false positives
* Improve investigation efficiency
* Strengthen regulatory compliance

---

## Team

HackMan (solo team) - Pavanakumar Harigadde
Hackathon Submission – PS4 Data Access Anomaly Detection Challenge
