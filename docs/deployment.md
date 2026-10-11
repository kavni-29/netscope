# NetScope Deployment & Distribution Guide

This document outlines the end-to-end procedures for deploying, publishing, and distributing NetScope across various targets.

---

## 1. Pushing to GitHub

Your local repository is initialized, committed, and already configured with your remote:
- **Remote URL**: `git@github.com:kavni-29/netscope.git`
- **Authenticated User**: `kavni-29` (SSH key verified)

### Step 1: Create the Empty Repository on GitHub
Because GitHub does not allow creating new repositories over pure SSH, create the repository shell on GitHub:
1. Open your browser and go to: **[https://github.com/new](https://github.com/new)**
2. Set **Repository name** to: `netscope`
3. Description: `NetScope — Network Traffic Analyzer & Explainable Anomaly Detection System`
4. Set visibility to **Public** (recommended for portfolio) or **Private**.
5. **IMPORTANT**: Leave *"Add a README file"*, *"Add .gitignore"*, and *"Choose a license"* **UNCHECKED** (the local project already has all of these).
6. Click **Create repository**.

### Step 2: Push Your Local Code
Run this command from your terminal:
```powershell
cd "C:\Users\jivan\.gemini\antigravity\scratch\netscope"
git push -u origin main
```
*Your entire project, 34 automated tests, synthetic sample fixtures, documentation, and GitHub Actions CI workflow will be pushed.*

---

## 2. Automated Continuous Integration (CI/CD)

NetScope includes a pre-configured GitHub Actions workflow at [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

Once pushed, GitHub Actions automatically executes:
- Matrix tests across **Ubuntu Linux** and **Windows**.
- Python versions **3.10** and **3.11**.
- Runs the complete automated test suite (`pytest -v`).
- Executes the synthetic demonstration generator and CLI analysis verification.

You can monitor workflow runs under the **Actions** tab on your GitHub repository.

---

## 3. Local Desktop Deployment (Standard User)

For users or evaluators running NetScope from source:

```powershell
# 1. Clone repository
git clone https://github.com/kavni-29/netscope.git
cd netscope

# 2. Create isolated environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
# source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch Desktop GUI
python -m netscope.gui

# 5. Run CLI
python -m netscope.cli --input samples/synthetic_demo.pcap --output reports/demo --charts
```

---

## 4. Standalone Windows Executable Deployment (.exe)

To distribute NetScope to end-users without requiring Python or dependencies to be installed, compile a single standalone `.exe` using **PyInstaller**:

### Step 1: Install PyInstaller
```powershell
pip install pyinstaller
```

### Step 2: Build Standalone Application
```powershell
pyinstaller --noconsole --name "NetScope" --icon=NONE --collect-data scapy --collect-data matplotlib netscope/gui.py
```
- `--noconsole`: Suppresses background command terminal window for a clean desktop feel.
- `--name "NetScope"`: Names the resulting executable `NetScope.exe`.
- `--collect-data`: Packages Scapy protocol definitions and Matplotlib fonts/backends.

The compiled executable will be located in:
`dist/NetScope/NetScope.exe`

Users can simply double-click `NetScope.exe` to run the complete desktop application.

---

## 5. Python Package Distribution (PyPI / Wheel)

To build a standard Python `.whl` and `.tar.gz` package defined by [`pyproject.toml`](../pyproject.toml):

```powershell
# 1. Install build tools
pip install build twine

# 2. Build distribution archives
python -m build

# 3. Verify packages created in dist/
# NetScope-1.0.0-py3-none-any.whl
# NetScope-1.0.0.tar.gz

# 4. (Optional) Upload to PyPI
# python -m twine upload dist/*
```

Once installed via pip, users can invoke NetScope directly from any terminal:
```powershell
netscope --input capture.pcap --charts
netscope --gui
```
