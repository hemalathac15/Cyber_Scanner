# Cyber_Scanner
An AI-powered MCP security microservice and local RAG pipeline that orchestrates automated web crawling, semantic memory indexing (FAISS + Sentence-Transformers), live MITRE CVE API telemetry lookup, and local SLM analytical reasoning (gemma2:2b) over structured JSON schemas.

Cyber Scanner is a lightweight, local security analysis utility featuring an authentic **Model Context Protocol (MCP)** client-server architecture. The project orchestrates web crawling, semantic memory indexing, live vulnerability telemetry retrieval, and local Small Language Model (SLM) reasoning to produce structured risk and remediation packages.

---

## 🏗️ System Architecture

The following diagram illustrates how the asynchronous test client requests tools from the FastMCP server, coordinates the FAISS local database, fetches data from the MITRE API, and queries Ollama:
<img width="3600" height="2400" alt="image" src="https://github.com/user-attachments/assets/31c55b19-2cfa-4ee9-bb46-fb22f2dc2d0d" />


## 🚀 Key Features

* **MCP Server Integration:** Driven by `cyber_scan_server.py` using the **FastMCP** framework to seamlessly expose security automation tools over standard input/output (`stdio`).
* **Smart Crawler & Local RAG:** Dynamic web crawling via `BeautifulSoup` that automatically chunks text and creates dense vector embeddings via `SentenceTransformer` to query an in-memory `FAISS` database.
* **Live Telemetry Core:** Direct integration with the **MITRE CVE API** to pull down authenticated ground-truth vulnerability records (e.g., CVE-2024-3094) in real-time.
* **Local AI Intel Layer:** Communicates with a local **Ollama** engine pulling `gemma2:2b` to perform defensive impact evaluations and output deterministic, valid JSON payloads.
* **Automated Verification Client:** A robust `test_mcp_client.py` simulation harness to execute all script steps cleanly and capture telemetry down to local JSON data stores.

---

## 📁 Project Structure

```text
cyber_scanner/
├── .venv/                  # Python Virtual Environment (Ignored in Git)
├── outputs/                # Automated pipeline data package dumps
│   ├── crawler_output.json
│   ├── retrieval_output.json
│   ├── graph_output.json
│   └── final_context_package.json
├── cyber_scan_server.py    # Core FastMCP Server defining the security tool registry
├── test_mcp_client.py     # Asynchronous MCP Client processing pipeline execution
├── render_graph.py         # Dynamic node-and-edge matrix rendering utility
├── .gitignore              # Explicitly configured to exclude environments and caches
└── README.md               # Project documentation

Prerequisites
Python 3.10 to 3.14

Git

Ollama Desktop App (Installed and running in the background)

🛠️ Setup & Installation
1. Clone the Repository
PowerShell
git clone [https://github.com/hemalathac15/Cyber_Scanner.git](https://github.com/hemalathac15/Cyber_Scanner.git)
cd Cyber_Scanner
2. Configure the Isolated Virtual Environment
Windows (PowerShell):

PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
macOS / Linux:

Bash
python3 -m venv .venv
source .venv/bin/activate
3. Install All Ecosystem Dependencies
Ensure your package manager is updated and run the installation script block to satisfy all server-side AI and infrastructure prerequisites:

PowerShell
python -m pip install --upgrade pip
python -m pip install mcp fastmcp requests beautifulsoup4 numpy sentence-transformers torch faiss-cpu fastapi uvicorn pydantic ollama

4. Fetch the Local SLM Intelligence Engine
Make sure your Ollama instance is active in the background, then pull down the required ultra-lightweight reasoning model:

PowerShell
ollama pull gemma2:2b

💻 Usage
To execute the entire pipeline simulation—which initializes the background MCP server, runs the web crawler sandbox, performs vector searches, verifies CVE truth data, maps a network topology graph, and runs the SLM risk generator—execute the main test runner:

PowerShell
python test_mcp_client.py
Viewing Pipeline Outputs
Upon successful execution, the script will write clean, production-ready matrices directly to the outputs/ folder. You can evaluate the finalized automated reporting matrix inside outputs/final_context_package.json:

JSON
{
    "query_id": "q_12345",
    "context": [
        {
            "doc_id": "doc_456",
            "content": "ALERT: System scan flagged a match for structural risk.\nContext details:\n{ \n  \"cve_id\": \"CVE-2024-3094\",\n  \"status\": \"Found\",\n  \"source\": \"MITRE Ground Truth API\",\n  \"description\": \"Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. \r\nThrough a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.\"\n},",
            "source": "MITRE Ground Truth API",
            "chunk_id": "c_001",
            "score": 0.92
        }
    ],
    "suggested_remediations": [
        "Implement strict input validation, upgrade affected components to the latest patched version, or deploy specific WAF rules."
    ],
    "references": [
        "doc_456"
    ]
}

---

### How to Update This on GitHub

Run this clean terminal command chain to push your newly polished documentation straight to your repository:

```powershell
# 1. Stage the modified README file
git add README.md

# 2. Commit the documentation change
git commit -m "Docs: Update README with comprehensive setup instructions, local RAG architecture, and architecture diagrams"

# 3. Push to your live main branch
git push origin main
├── .gitignore             # Configured to exclude local venv files
└── README.md              # Project documentation
