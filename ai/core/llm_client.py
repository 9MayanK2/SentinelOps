"""
llm_client.py

Multi-Provider LLM Client for DevSecOps Security Remediation.
Supports OpenAI API, Google Gemini API, Ollama (Local LLM), and Mock Fallback Engine.
"""

from __future__ import annotations

import os
import json
import logging
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional
# Load root workspace .env first, then ai/.env
root_env = Path(__file__).parent.parent.parent / ".env"
ai_env = Path(__file__).parent.parent / ".env"
if root_env.exists():
    load_dotenv(root_env)
if ai_env.exists():
    load_dotenv(ai_env, override=True)

logger = logging.getLogger("DevSecOps-AI-LLM")


class LLMClient:
    """
    Unified client for invoking Large Language Models to generate security remediations.
    Configured for Ollama local LLM execution.
    """

    def __init__(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.provider = (provider or os.getenv("LLM_PROVIDER", "ollama")).lower()
        self.model = model or os.getenv("OLLAMA_MODEL") or os.getenv("LLM_MODEL", "llama3.1")
        self.api_key = api_key or os.getenv("OPENAI_API_KEY") or os.getenv("GEMINI_API_KEY")

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Generates completion from configured LLM provider.
        Defaults to local Ollama LLM for 100% offline security advisories.
        """
        if self.provider == "ollama":
            host = os.getenv("OLLAMA_HOST") or os.getenv("OLLAMA_BASE_URL") or "http://localhost:11434"
            ollama_model = self.model or "llama3.1"
            
            # Try /api/chat first, then /api/generate
            try:
                chat_url = f"{host.rstrip('/')}/api/chat"
                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                messages.append({"role": "user", "content": prompt})

                payload = {
                    "model": ollama_model,
                    "messages": messages,
                    "stream": False
                }
                res = requests.post(chat_url, json=payload, timeout=30)
                if res.status_code == 200:
                    data = res.json()
                    content = data.get("message", {}).get("content", "").strip()
                    if content:
                        return content
            except Exception as chat_err:
                logger.debug(f"Ollama chat API call failed ({chat_err}), trying generate endpoint...")

            try:
                gen_url = f"{host.rstrip('/')}/api/generate"
                payload = {
                    "model": ollama_model,
                    "prompt": f"{system_prompt or ''}\n\n{prompt}",
                    "stream": False
                }
                res = requests.post(gen_url, json=payload, timeout=30)
                if res.status_code == 200:
                    data = res.json()
                    content = data.get("response", "").strip()
                    if content:
                        return content
            except Exception as gen_err:
                logger.warning(f"Ollama local LLM call failed ({gen_err}). Falling back to Local Security Engine.")

        elif self.provider == "openai" and os.getenv("OPENAI_API_KEY"):
            try:
                import openai
                client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                messages.append({"role": "user", "content": prompt})

                response = client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=0.2,
                    max_tokens=1500,
                )
                return response.choices[0].message.content.strip()
            except Exception as err:
                logger.warning(f"OpenAI API call failed ({err}). Falling back to Local Security Engine.")

        elif self.provider == "gemini" and os.getenv("GEMINI_API_KEY"):
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={os.getenv('GEMINI_API_KEY')}"
                payload = {
                    "contents": [{"parts": [{"text": f"{system_prompt or ''}\n\n{prompt}"}]}]
                }
                res = requests.post(url, json=payload, timeout=15)
                if res.status_code == 200:
                    data = res.json()
                    return data['candidates'][0]['content']['parts'][0]['text'].strip()
            except Exception as err:
                logger.warning(f"Gemini API call failed ({err}). Falling back to Local Security Engine.")

        # Fallback Mock / Local Security Engine
        return self._generate_heuristic_response(prompt)


    def _generate_heuristic_response(self, prompt: str) -> str:
        """
        Generates structured, professional security remediation response using rule heuristics.
        """
        finding_id = "N/A"
        rule_id = "N/A"
        tool = "Security Scanner"
        severity = "HIGH"

        lines = prompt.split("\n")
        for line in lines:
            if line.startswith("Finding ID:"):
                finding_id = line.split(":", 1)[1].strip()
            elif line.startswith("Rule ID:"):
                rule_id = line.split(":", 1)[1].strip()
            elif line.startswith("Tool / Scanner:"):
                tool = line.split(":", 1)[1].strip()
            elif line.startswith("Severity:"):
                severity = line.split(":", 1)[1].strip()

        return f"""
### 🛡️ SentinelOps AI Remediation Advisory

**Finding Reference**: Finding #{finding_id} ({tool} - `{rule_id}`)
**Risk Level**: `{severity}`

#### 1. 🔍 Root Cause Analysis
The security finding `{rule_id}` represents a potential risk in software design or configuration. Insecure handling of input, missing access controls, or unhardened container settings allow adversaries to disrupt application integrity.

#### 2. 🛠️ Actionable Remediation Plan
1. **Sanitize & Validate Input**: Enforce strict data type checking and parameterization across all external interfaces.
2. **Apply Security Controls**: Enforce least privilege, parameterization, or proper secret isolation via environment variables.
3. **Automate Pipeline Validation**: Integrate pre-commit hooks and static analysis gates in CI/CD build scripts.

#### 3. 💻 Code Comparison (Before vs. After)

**❌ Vulnerable Implementation:**
```python
# Unsanitized dynamic execution or hardcoded credential
raw_data = request.args.get('input')
execute_query(f"SELECT * FROM records WHERE id = '{{raw_data}}'")
```

**✅ Remediated Implementation:**
```python
# Parameterized query handling preventing injection
safe_data = request.args.get('input')
execute_query("SELECT * FROM records WHERE id = %s", (safe_data,))
```

#### 4. 📊 Regulatory & Compliance Alignment
- **OWASP Top 10**: A03:2021-Injection / A05:2021-Security Misconfiguration
- **NIST CSF**: PR.DS-5 (Data Protection & Integrity)
- **CIS Controls**: Control 16 (Application Software Security)
""".strip()
