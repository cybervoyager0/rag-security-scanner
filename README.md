# 🛡️ Custom RAG Security Assessment & Evaluation Suite

An automated red-teaming and security assessment framework designed specifically for AI Chatbots and Retrieval-Augmented Generation (RAG) pipelines. 

This tool helps security engineers and developers audit LLM-based applications for vulnerabilities before deploying them to production.

---

## 🚀 Key Features

* **Prompt Injection Testing:** Evaluates if the target chatbot can be hijacked using direct or indirect prompt injection payloads.
* **Context & Data Leakage Detection:** Checks if the RAG system accidentally exposes internal database configurations, PII, or confidential documents.
* **Jailbreak & System Prompt Bypass:** Tests roleplay restrictions and developer-mode prompt extraction vulnerabilities.
* **Interactive Web Dashboard:** Built with Streamlit for real-time scan visualization, metrics, and progress tracking.
* **Reporting & Export:** Export scan results and detailed logs instantly into JSON and CSV formats.

---

## 🛠️ Tech Stack

* **Python**
* **Streamlit** (Interactive GUI Dashboard)
* **Requests** (API Testing Engine)
* **Pandas** (Data Processing & Reporting)

---

## ⚙️ Local Installation & Running

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/cybervoyager0/rag-security-scanner.git](https://github.com/cybervoyager0/rag-security-scanner.git)
   cd rag-security-scanner
