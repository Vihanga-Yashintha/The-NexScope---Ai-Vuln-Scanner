
# **NexScope – Web Vulnerability Scanning Toolkit (GUI + Integration + Reporting)**

NexScope is a desktop-based security analysis toolkit that integrates traditional reconnaissance scanners with machine-learning–based vulnerability prediction.
This repository represents **Part 3 of the NexScope Final Year Project**, focusing on:

* 🌐 **Graphical User Interface (GUI)**
* 🔗 **Module Integration (Scanner + ML Model)**
* 📡 **Real-Time Scan Logging**
* 📁 **Scan History Management**
* 📄 **HTML/PDF Report Generation**

NexScope provides an accessible user-facing environment to run scans, view results, store history, and generate export-ready reports.

---

## **✨ Features**

### **✔ Modern Tkinter GUI**

* User-friendly interface for managing scans
* Tabs for **Scan**, **History**, **Report**, and **Settings**
* Non-blocking execution with threading support

### **✔ Full Pipeline Integration**

* Connects to:

  * Scanning module (Nmap, Gobuster, Nikto)
  * Machine Learning Prediction API
* Displays structured results and ML-generated CVSS estimates

### **✔ Real-Time Logs**

* Live terminal-style output feed
* Time-stamped logs for scanner and ML events

### **✔ Report Generation (HTML & PDF)**

* Automatic creation of detailed vulnerability reports
* Includes:

  * Target metadata
  * Scanner results
  * Extracted features
  * Predicted vulnerabilities
  * CVSS score
* Export using **WeasyPrint** or **wkhtmltopdf**

### **✔ Scan History Management**

* Saves every scan with timestamp + structured JSON
* View, reload, and re-export past results

---

## **📦 Installation**

### **Requirements**

* Python **3.9+**
* Linux recommended (Tkinter, WeasyPrint compatibility)
* Tool dependencies listed in `requirements.txt`

### **Setup**

```bash
git clone https://github.com/<your-username>/NexScope.git
cd NexScope

python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

---

## **🚀 Run the Application**

```bash
python3 nexscope_gui.py
```

Before running the GUI, ensure:

* The Scanner Module (Part 1) is installed and reachable
* The ML Prediction API (Part 2) is running or properly configured

---

## **📁 Project Structure**

```
NexScope/
│
├── gui/
│   ├── nexscope_gui.py        # Main application entrypoint
│   ├── components/            # Reusable UI components
│   ├── styles/                # Theme, color schemes
│   └── utils/                 # Threading, logs, validation helpers
│
├── integration/
│   ├── scan_controller.py     # Controls scanner execution
│   └── api_connector.py       # Connects to ML prediction API
│
├── reporting/
│   ├── report_generator.py    # HTML & PDF generator
│   ├── templates/             # HTML templates
│   └── assets/                # CSS, icons, images
│
└── history/
    ├── history_manager.py     # Scan storage & retrieval
    └── records/               # Saved scan results
```

---

## **📝 Report Generation**

### Generate HTML Report

```bash
python3 report_generator.py --input results.json --out report.html
```

### Convert HTML to PDF

Using WeasyPrint:

```bash
weasyprint report.html report.pdf
```

Using wkhtmltopdf:

```bash
wkhtmltopdf --enable-local-file-access report.html report.pdf
```

The GUI automates both steps after each scan.

---

## **⚠️ Ethical Usage**

NexScope is a security research tool.
You **must** follow these ethical guidelines:

* Only scan systems you **own** or have **explicit authorization** to test
* Do not distribute sensitive scanner output
* Misuse of this tool for illegal hacking is strictly prohibited

---

## **📜 License**

Released under the **MIT License**.
See `LICENSE` for details.

---
