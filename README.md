# 🔍 Signature-Scanner

A lightweight malware detection tool that combines **signature-based scanning**, **heuristic checks**, and an optional **GUI interface**.  
The project demonstrates how executables can be analyzed for potential threats using static methods like YARA rules, entropy calculation, and suspicious API detection.

---

## 📂 Project Structure
malware-scanner/
│── build/ # Build artifacts
│── dist/ # Distribution files (executables after packaging)
│── signatures/ # YARA/signature rules
│── gui.py # GUI interface for the scanner
│── gui.spec # PyInstaller spec file for building executables
│── heuristics.py # Heuristic-based detection methods
│── scanner.py # Main command-line scanner
│── scan_report_<date>.txt # Example scan reports

---

## ✨ Features
- **Signature Matching** – Uses YARA rules stored in `/signatures/` to detect known threats.  
- **Heuristic Analysis** – Flags suspicious patterns, APIs, and behaviors.  
- **Entropy Analysis** – Detects compressed/packed binaries.  
- **Report Generation** – Creates timestamped scan reports.  
- **GUI Support** – Easy-to-use interface for non-technical users.  
- **Executable Packaging** – Can be built as a standalone EXE using PyInstaller.  

---

## 🛠️ Installation
Clone this repository and install dependencies:

```bash
git clone https://github.com/your-username/malware-scanner.git
cd malware-scanner
pip install -r requirements.txt
