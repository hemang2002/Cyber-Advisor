# Cybersecurity Threat Detection and Awareness Platform

## 🛡️ Overview

As cyber threats continue to grow in complexity and volume, many individuals—especially those without formal training—struggle to understand or defend against them. This project presents an integrated, AI-powered cybersecurity platform that simplifies threat detection, education, and response for everyday users.

The platform combines multiple cyber intelligence tools and state-of-the-art machine learning models to provide services such as data breach detection, sentiment and misinformation analysis, phishing and malware scanning, and deepfake identification. A built-in AI advisor delivers expert guidance and clear mitigation steps in real time.

---

## 🎯 Key Features

- **Data Breach Lookup**: Check if an email address has been compromised using trusted breach databases.
- **Phishing & Malware Detection**: Analyze URLs, IPs, and files for malicious intent and phishing characteristics.
- **Deepfake Detection**: Inspect uploaded media using ML models to identify AI-generated forgeries.
- **Sentiment & Misinformation Analysis**: Evaluate text for manipulative emotional tones and false claims.
- **Automated Summary & Severity Reporting**: Generate human-readable, AI-generated reports with severity levels.
- **Prevention Engine**: Fetch updated mitigation steps from the internet and simplify them for end-users.
- **Interactive Cybersecurity Advisor**: A context-aware chatbot that answers security questions and clarifies reports.

---

## 🧠 Models and APIs Utilized

- `prithivMLmods/Deep-Fake-Detector-Model` for image/video deepfake detection
- `llama3-8b-8192` for report summarization and severity assessment
- `llama-3.3-70b-versatile` for internet-based prevention retrieval
- `qwen-qwq-32b` for simplifying technical responses
- VirusTotal, XposedOrNot, Bloster APIs for scanning and breach lookups
- LangChain, LangGraph, LangSmith for LLM orchestration and memory
- Hugging Face, SerpAPI, Tavily for NLP models and search integration

---

## ⚙️ Technology Stack

### **Backend & AI Orchestration**
- **Python** – Core programming language
- **Flask** – Lightweight web application framework
- **LangChain / LangGraph / LangSmith** – Multi-agent coordination and LLM memory
- **Docker** – Containerization for deployment consistency

### **Frontend**
- **HTML / CSS / JavaScript** – UI/UX development
- **Jinja2 (Flask templates)** – Dynamic content rendering

### **DevOps & Tools**
- **Google AI Studio** – Model fine-tuning and experimentation
- **Git** – Version control and collaboration
- **Hugging Face** – Model hosting and integration
- **SerpAPI & Tavily** – Web search APIs for threat prevention lookups


---

## 🚀 Getting Started

### Prerequisites

- Python 3.9+
- Git
- Docker (optional)
- API keys for:
  - VirusTotal
  - SerpAPI
  - Tavily
  - XposedOrNot
  - Hugging Face access token

### Setup Instructions

1. **Clone the Repository**
   ```bash
   git clone https://github.com/your-username/cybersecurity-platform.git
   cd cybersecurity-platform

2. **Create a Virtual Environment**
   ```bash
   python -m venv venv
   venv\Scripts\activate

3. **Install Dependencies**
    ```bash
    pip install -r requirements.txt

4. **Configure Environment Variables**:
     ```bash
    GROQ_API_KEY =
    TAVILY_API_KEY = 
    BLOSTER_API_KEY = 
    SERPER_API = 
    DEEP_FAKE_NAME = "prithivMLmods/Deep-Fake-Detector-Model"
    VIRUSTOTAL_API = 
    LANGSMITH_API_KEY = 
    MODEL_NAME = "prithivMLmods/Deep-Fake-Detector-Model"
    GOOGLE_API_KEY =

5. **Create docker images**     
     ```bash
     docker build -t chatbot-image .
     cd src
     docker build -t module-cyber -f Dockerfile.module .
     docker build -t summary -f Dockerfile.summary .
     cd ..

6. **Run Docker**
     ```bash
     docker run -d -p 5000:5000 --name chatbot-container chatbot-image

7. **Run app**
     ```bash
     python app.py

---
🧠 Advisor Module
The built-in AI advisor can:

Answer cybersecurity questions

Clarify detected threat reports

Reference up to 20 past user queries for contextual awareness

It is powered by a combination of LangChain and large language models, giving users access to expert guidance in real time.
---

📈 Future Enhancements
Real-time threat dashboard

Browser plugin integration

Multi-language support

Role-based user profiles

Integration with antivirus tools
