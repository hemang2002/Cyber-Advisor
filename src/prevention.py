# type: ignore

import os
import json
from typing import Dict
from langchain_groq import ChatGroq
from langchain_core.prompts import PromptTemplate
from langchain.agents import AgentExecutor, create_react_agent, Tool
from langchain_community.utilities import SerpAPIWrapper

import warnings
warnings.filterwarnings("ignore")

from dotenv import load_dotenv
load_dotenv()

def initialize_cybersecurity_agent() -> AgentExecutor:
    """Initialize the cybersecurity fact-checking agent."""
    
    llm = ChatGroq(
        model_name="llama-3.3-70b-versatile",
        groq_api_key=os.getenv("GROK_API_KEY"),
        temperature=0.2
    )

    search = SerpAPIWrapper(serpapi_api_key=os.getenv("SERPER_API_KEY"))
    research_tools = Tool(
        name="Search",
        func=search.run,
        description="Useful for answering questions about current events"
    )
    tools = [research_tools]

    research_prompt = PromptTemplate.from_template("""You are a cybersecurity expert researcher.
    Search for accurate, detailed, and concise prevention strategies for cyberattacks provided by normal person in form of report.
    Focus on step-by-step methods to prevent attacks and summarize the attack lifecycle (reconnaissance, initial access, execution, persistence, exfiltration).
    Provide clear, actionable steps to disrupt attacks at each lifecycle stage.
    Avoid opinions, vague advice, or irrelevant details.
    Return a concise summary with numbered steps.
    You have access to the following tools:

    {tools}

    Use the following format:

    Question: the input question you must answer
    Thought: you should always think about what to do
    Action: the action to take, should be one of [{tool_names}]
    Action Input: the input to the action
    Observation: the result of the action
    ... (this Thought/Action/Action Input/Observation can repeat one time)
    Thought: I now know the final answer
    Final Answer: the final answer to the original input question

    Begin!

    Question: {input}
    Thought:{agent_scratchpad}
    """)

    # Initialize agent
    fact_check_agent = create_react_agent(llm, tools, research_prompt)
    return AgentExecutor(
        agent=fact_check_agent,
        tools=tools,
        handle_parsing_errors=True
    )

def run_fact_check_agent(agent_executor: AgentExecutor, problem: str) -> Dict:
    """Run the fact-checking agent on the given problem."""
    try:
        result = agent_executor.invoke({"input": problem})
        return result
    except Exception as e:
        return {"error": f"Error during search: {str(e)}"}

def explain_in_simple_terms(text: str) -> str:
    """Explain cybersecurity text in simple, beginner-friendly language."""
    llm = ChatGroq(
        model_name="qwen-qwq-32b",
        groq_api_key=os.getenv("GROK_API_KEY"),
        temperature=0.2
    )
    prompt = f"""
    You are an expert cybersecurity teacher. Read the research text and explain it in very simple words.
    Use beginner-friendly language, short sentences, and analogies (e.g., compare cyberattacks to locking a house).
    Break down each step clearly and provide a numbered list of prevention actions.
    Avoid technical jargon and focus on practical advice.

    Research Text:
    \"\"\"
    {text}
    \"\"\"
    """
    return llm.invoke([("human", prompt)]).content

def findPrevention(problem: str) -> Dict:
    """Main function to run the cybersecurity expert system."""
    
    agent_executor = initialize_cybersecurity_agent()
    
    search_result = run_fact_check_agent(agent_executor, problem)
    print("Search Result:", search_result)
    
    explanation = explain_in_simple_terms(str(search_result))
    
    return explanation

# if __name__ == "__main__":
#     text = """This report summarizes two data breaches: "Gaadi" and "Dailymotion". The breaches occurred in 2015 and 2016, respectively.
#     The report provides detailed information about the breaches, including the industries affected, the type of data exposed, and the password risk.
#     The data exposed includes personal identification, security practices, communication and social interactions, demographics, and device and network information.
#     The report also includes a summary of the breaches, highlighting the importance of password security and the need for users to change their passwords regularly."""
#     print(findPrevention(text))#os.environ.get('TEXT_INPUT', "TEXT_INPUT"))