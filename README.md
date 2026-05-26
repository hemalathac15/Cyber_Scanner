# Cyber_Scanner
An AI-powered MCP microservice and local RAG pipeline using Python, FAISS, and Sentence-Transformers to crawl web assets and semantically query real-time security threat intelligence.

# Mini Cyber Scanner

Mini Cyber Scanner is a lightweight, Python-based network utility featuring a Model Context Protocol (MCP) client-server architecture. The project is designed to scan endpoints, log security metrics, and interface seamlessly with LLM orchestrators or desktop tools using the MCP standard.

## 🚀 Features

* **MCP Server Integration:** Dedicated `cyber_scan_server.py` exposed as an MCP host to provide security scanning tools to AI models.
* **Automated Testing Client:** Built-in `test_mcp_client.py` script to simulate query scenarios and validate server connectivity and response shapes.
* **Isolated Environment:** Configured with a dedicated Python virtual environment (`venv`) to ensure reproducible dependencies.

## 📁 Project Structure

```text
MINI_CYBER_SCANNER/
├── venv/                  # Python Virtual Environment (ignored in git)
├── cyber_scan_server.py   # Core MCP Server handling scan logic
├── test_mcp_client.py    # Test suite for client-server verification

Prerequisites
Python 3.10 or higher

Git

1. Clone the Repository
git clone [https://github.com/hemalathac15/Cyber_Scanner.git](https://github.com/hemalathac15/Cyber_Scanner.git)
cd Cyber_Scanner

2. Set Up the Virtual Environment
Activate the environment based on your operating system:

Windows (PowerShell):
python -m venv venv
.\venv\Scripts\Activate.ps1

macOS / Linux:

Bash
python3 -m venv venv
source venv/bin/activate

3. Install Dependencies
Ensure your environment package installer is up to date and install required core libraries (such as mcp or framework packages):

Bash
pip install --upgrade pip
# pip install -r requirements.txt (Add your specific packages here)

💻 Usage
Running the MCP Server
To spin up the server pipeline backend:

Bash
python cyber_scan_server.py
Testing the Client Connection
In a separate terminal window (with the venv active), run the test client script to verify payload transfers:

Bash
python test_mcp_client.py
├── .gitignore             # Configured to exclude local venv files
└── README.md              # Project documentation
