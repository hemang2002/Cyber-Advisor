# type: ignore
import json
from langchain_groq import ChatGroq
from langchain.schema import SystemMessage, HumanMessage
from typing import Dict
import re
import os

from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())


def generate_prompt(report_json: Dict) -> list:
    system_message = SystemMessage(
        content=(
            """You are a cybersecurity intelligence analyst with deep expertise in interpreting structured data. 
            Your task is to analyze incoming JSON-formatted cyber reports and provide a clear, concise, and technically accurate explanation of their contents.
            Focus on identifying and explaining key indicators, threat actors, attack vectors, vulnerabilities, and potential impacts. 
            Your analysis should be suitable for non technical audiences.\n\n"""
            "Your response must include exactly three parts:\n"
            "1. Summary: a detail explanation of the report (under 500 words), explaining any technical terms in simple words and highlight anu important information.\n"
            "2. Classification: one word (e.g., high, medium, low).\n"
            "3. Prevention Required: always select one word between (Yes or No).\n\n"
            "Respond in plain format, starting with the keywords:\n"
            "Summary: ...\nClassification: ...\nPrevention Required: ..."
        )
    )

    user_prompt = f"Analyze the following JSON report:\n```json\n{json.dumps(report_json, indent=2)}\n```"
    user_message = HumanMessage(content=user_prompt)

    return [system_message, user_message]

def parse_analysis_to_json(text: str) -> Dict:
    summary_match = re.search(r"Summary:\s*(.+?)(?:\nClassification:|\Z)", text, re.DOTALL)
    classification_match = re.search(r"Classification:\s*(\w+)", text)
    prevention_match = re.search(r"Prevention Required:\s*(Yes|No)", text, re.IGNORECASE)

    return {
        "summary": summary_match.group(1).strip() if summary_match else None,
        "severity": classification_match.group(1).strip() if classification_match else None,
        "prevention_required": prevention_match.group(1).strip().capitalize() if prevention_match else None
    }

def analyze_json_report(report_json: Dict, llm) -> Dict:
    messages = generate_prompt(report_json)
    response = llm.invoke(messages)
    return parse_analysis_to_json(response.content)

if __name__ == "__main__":

    GROQ_API_KEY = os.environ.get('GROK_API_KEY')
    RESULT = os.environ.get('RESULT', {})
    llm = ChatGroq(
        groq_api_key=GROQ_API_KEY,
        model_name="llama3-8b-8192"
    )
    analysis_result = analyze_json_report(RESULT, llm)

    print(json.dumps(analysis_result))