import json
import re
import os
import warnings
warnings.filterwarnings("ignore")

from typing import Dict, Any
from langchain_groq import ChatGroq
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from langchain.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import PromptTemplate
from langchain_community.utilities import SerpAPIWrapper
from langchain_core.tools import Tool
from dotenv import load_dotenv

load_dotenv()


def findSentiment(text_input, groq_api_key):

    try:
        llm = initialize_llm(groq_api_key)

        prompt_template = PromptTemplate(
            input_variables=["text"],
            template="""
            Analyze the sentiment of the following text. Provide the output in the following format:

            Summary: <Provide a concise summary of the text in under 200 words.>
            Tone: <Describe the tone of the text using one words.>
            Sentiment: <Always categorize the overall sentiment of the text as positive, negative, or neutral.>

            Text: {text}
            """)

        sentiment_analysis_chain = LLMChain(llm=llm, prompt=prompt_template)

        result = sentiment_analysis_chain.run(text=text_input)

        summary_match = re.search(r"Summary:\s*(.*)", result)
        tone_match = re.search(r"Tone:\s*(.*)", result)
        sentiment_match = re.search(r"Sentiment:\s*(\w+)", result)

        result_dict = {
            "status": "success",
            "summary": summary_match.group(1).strip() if summary_match else "",
            "tone": tone_match.group(1).strip() if tone_match else "",
            "sentiment": sentiment_match.group(1).strip() if sentiment_match else ""
        }

        return json.dumps(result_dict, indent=2)
    
    except Exception as e:
        return json.dumps({
            "status": "error",
            "error_message": str(e)
        })


def initialize_llm(groq_api_key: str) -> ChatGroq:
    """Initialize the language model with given parameters."""
    return ChatGroq(
        groq_api_key=groq_api_key,
        model_name="llama3-8b-8192",
        temperature=0.3
    )


def create_search_tool(serpapi_key: str) -> Tool:
    """Create and configure the search tool."""
    search = SerpAPIWrapper(serpapi_api_key=serpapi_key)
    return Tool(
        name="Search",
        func=search.run,
        description="Useful for answering questions about current events"
    )


def create_fact_check_prompt() -> PromptTemplate:
    """Create the fact-checking prompt template."""
    return PromptTemplate.from_template("""
    You are a fact-checking journalist. Verify the accuracy of news facts in this article: {input}.
    You have access to the following tools:
    {tools}
    Use the following format:

    Question: the input question you must answer
    Thought: you should always think about what to do
    Action: the action to take, should be one of [{tool_names}]
    Action Input: the input to the action
    Observation: the result of the action
    ... (this Thought/Action/Action Input/Observation can repeat 3 times)
    Thought: I now know the final answer
    Final Answer: A detailed explanation of the fact-checking results, followed by a one-word verdict indicating if the article contains fake information: "True" (fake) or "False" (not fake).

    Begin!
    Question: {input}
    Thought:{agent_scratchpad}
    """)


def initialize_fact_checker(llm: ChatGroq, tools: list[Tool], prompt: PromptTemplate) -> AgentExecutor:
    """Initialize the fact-checking agent executor."""
    fact_check_agent = create_react_agent(llm, tools, prompt)
    return AgentExecutor(
        agent=fact_check_agent,
        tools=tools,
        handle_parsing_errors=True
    )


def fact_check_article(article_text: str, groq_key: str) -> str:
    """
    Fact-check an article and return the results.
    
    Args:
        article_text: The text of the article to fact-check
        groq_key: The API key for Groq
        
    Returns:
        JSON string containing fact-checking results
    """
    try:
        serpapi_key = os.getenv("SERPER_API_KEY")  # Corrected environment variable name
        if not serpapi_key:
            raise ValueError("SERPAPI_API_KEY environment variable not set")
        
        llm = initialize_llm(groq_key)
        search_tool = create_search_tool(serpapi_key)
        prompt = create_fact_check_prompt()
        fact_checker = initialize_fact_checker(llm, [search_tool], prompt)
        
        result = fact_checker.invoke({"input": article_text})
        
        verdict = "Unknown"
        if isinstance(result, dict) and "output" in result:
            output = result["output"]
            if isinstance(output, str):
                verdict = output.split()[-1] if output else "Unknown"
        
        return json.dumps({
            "status": "success",
            "fact_check_results": result,
            "is_fake": verdict
        }, indent=2)
        
    except Exception as e:
        return json.dumps({
            "status": "error",
            "error_message": str(e),
            "is_fake": "Unknown"
        }, indent=2)


def main():
    text_input = os.environ.get('TEXT_INPUT', "TEXT_INPUT")
    SELECT = os.environ.get('SELECT', 'SELECT')
    groq_api_key = os.getenv("GROK_API_KEY")
    if text_input and groq_api_key:
        if SELECT == "sentiment":
            result = findSentiment(text_input, groq_api_key)
        elif SELECT == "fake_news":
            result = fact_check_article(text_input, groq_api_key)
    
    print(result)

if __name__ == "__main__":

    main()