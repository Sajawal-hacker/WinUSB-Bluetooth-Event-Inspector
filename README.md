# 🔍 WinUSB & Bluetooth Event Inspector

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![GUI](https://img.shields.io/badge/GUI-PySide6-orange)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-success)

---

## 🚀 Overview

**WinUSB & Bluetooth Event Inspector** is a Windows-based Digital Forensics tool developed for analyzing USB and Bluetooth device connection artifacts using Event Logs and system traces.

Designed for:

- Digital Forensics Investigators (DFIR)
- SOC Analysts
- Incident Response Teams
- Cybersecurity Researchers
- Students & Security Enthusiasts

---

## ✨ Core Features

### 🔐 Security

- Automatic Administrator Privilege Detection
- Secure Log Inspection
- Controlled Report Generation

### 🔍 Log Inspection

- USB Device Connection History
- Bluetooth Pairing & Connection Logs
- First Connected Timestamp
- Last Connected Timestamp
- Device Serial / MAC Address
- Connection Duration Tracking

### 📊 GUI Features

- Modern Dark Theme Interface
- Tab-Based Navigation
- Search & Filter Functionality
- Delete Log Entries
- Clean Data Table Display

### 📁 Reporting

- Export to Excel (.xlsx)
- Export to PDF (.pdf)
- Windows System Metadata in Reports
- Structured & Professional Report Layout

### ⚙ System Integration

- Windows Event Log (EVTX) Analysis
- Registry Artifact Inspection
- Real-time Log Fetch Button

---

## 🛠 Technology Stack

- Python 3.10+
- PySide6 (GUI Framework)
- Pandas (Data Processing)
- ReportLab (PDF Reports)
- pywin32 (Windows API)
- Windows Event Logs

---

## 📦 Installation

```bash
git clone https://github.com/yourusername/WinUSB-Bluetooth-Event-Inspector.git
cd WinUSB-Bluetooth-Event-Inspector
pip install -r requirements.txt
python main.py
```
