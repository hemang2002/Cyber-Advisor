# type: ignore

from flask import Flask, request, jsonify
from typing import Annotated, Optional, Literal
from typing_extensions import TypedDict
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langchain_core.messages import HumanMessage, AIMessage
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq
from langchain.memory import ConversationBufferMemory
import os
from dotenv import load_dotenv
from tavily import TavilyClient
import uuid

load_dotenv()

app = Flask(__name__)

class State(TypedDict):
    messages: Annotated[list, add_messages]
    reference_text: Optional[str]
    memory: ConversationBufferMemory
    optimized_prompt: Optional[str]
    route_decision: Optional[str]
    session_id: Optional[str]
    needs_prompt_engineering: Optional[bool]

class RouteQuery(BaseModel):
    datasource: Literal["search_tavily", "direct"] = Field(
        ...,
        description="""Choose 'search_tavily' for questions about recent/latest cybersecurity trends,
        news, CVEs, or exploits. Choose 'direct' for general cybersecurity knowledge,
        concepts, or advice.""",
    )

class ClassifierDecision(BaseModel):
    needs_prompt_engineering: bool = Field(
        ...,
        description="Indicates whether the query requires prompt engineering."
    )

def load_session_memory(session_id: str) -> ConversationBufferMemory:
    return SESSION_MEMORY_STORE.get(session_id)

def save_session_memory(session_id: str, memory: ConversationBufferMemory):
    SESSION_MEMORY_STORE[session_id] = memory

def query_classifier(state: State):
    last_message = state["messages"][-1]
    memory = state.get("memory", ConversationBufferMemory(return_messages=True, max_messages=10))
    session_id = state.get("session_id", str(uuid.uuid4()))

    if not isinstance(last_message, HumanMessage):
        return {
            "messages": [AIMessage(content="Invalid input. Please provide a question.")],
            "needs_prompt_engineering": False,
            "memory": memory,
            "session_id": session_id,
            "optimized_prompt": ""
        }

    query = last_message.content.strip()
    word_count = len(query.split())
    char_count = len(query)

    classifier_prompt = ChatPromptTemplate.from_messages([
        ("system", """You are an expert query classifier. Your task is to determine if the user's query requires prompt engineering. Prompt engineering is needed for complex, ambiguous, or multi-part questions that benefit from rephrasing for clarity and specificity. Short, direct, or simple queries (e.g., one word, one line, or clear questions) should bypass prompt engineering.

        Guidelines:
        - Queries with <= 3 words or <= 20 characters are typically direct.
        - Queries that are clear and specific (e.g., "Define malware") are direct.
        - Queries that specify number of line for output (e.g., Explain me in one line).
        - Queries that specify any text to be explained in specific number of line (e.g., Explain this from reference text in one line).
        - Queries with multiple parts, ambiguous terms, or requiring context (e.g., "What are todays news about malware?") need prompt engineering.

        Return a JSON object with a single key 'needs_prompt_engineering' and value must be either true or false. If unsure, always return 'needs_prompt_engineering' as false."""),
        ("human", "{query}")
    ])

    llm_classifier = ChatGroq(groq_api_key=os.getenv("GROQ_API_KEY"), model="gemma2-9b-it", temperature=0.3)
    structured_llm_classifier = llm_classifier.with_structured_output(ClassifierDecision)
    chain = classifier_prompt | structured_llm_classifier
    decision = chain.invoke({"query": query})

    # For direct queries, set optimized_prompt to the original query
    optimized_prompt = query if not decision.needs_prompt_engineering else ""

    return {
        "needs_prompt_engineering": decision.needs_prompt_engineering,
        "optimized_prompt": optimized_prompt,
        "memory": memory,
        "session_id": session_id
    }

def prompt_engineering(state: State):
    last_message = state["messages"][-1]
    reference_text = state.get("reference_text", "")
    memory = state.get("memory", ConversationBufferMemory(return_messages=True, max_messages=10))
    session_id = state.get("session_id", str(uuid.uuid4()))

    if not isinstance(last_message, HumanMessage):
        return {
            "messages": [AIMessage(content="Invalid input. Please provide a question.")],
            "optimized_prompt": "",
            "memory": memory,
            "session_id": session_id
        }

    conversation_history = memory.load_memory_variables({})["history"]
    history_str = "\n".join([f"User: {m.content}" if isinstance(m, HumanMessage) else f"Assistant: {m.content}" for m in conversation_history])

    system_prompt = """
    You are an expert in prompt engineering. Your task is to transform the user's input question into an optimized prompt that is clear, concise, and tailored for an expert-level cybersecurity LLM agent. The optimized prompt should:
    - Clarify ambiguous terms or phrases.
    - Ensure the question is specific and focused to cyber-related queries.
    - Use technical terminology appropriate for cybersecurity professionals.
    - Preserve the original intent of the question.
    - Make the output easy to understand while maintaining an expert tone.
    - Incorporate relevant context from the conversation history and reference text to maintain continuity.
    - Explicitly align with the reference text's scope or content where relevant.

    Conversation History: {conversation_history}
    Reference Text: {reference_text}

    Return only the optimized prompt as a string and in least words."""
    
    prompt_engineer_prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "{question}")
    ])

    llm_prompt = ChatGroq(groq_api_key=os.getenv("GROQ_API_KEY"), model="gemma2-9b-it", temperature=0.3)
    chain = prompt_engineer_prompt | llm_prompt
    optimized_prompt = chain.invoke({
        "question": last_message.content,
        "conversation_history": history_str,
        "reference_text": reference_text
    }).content
    return {"optimized_prompt": optimized_prompt, "memory": memory, "session_id": session_id}

def routing_agent(state: State):
    optimized_prompt = state.get("optimized_prompt", "")
    memory = state.get("memory", ConversationBufferMemory(return_messages=True, max_messages=10))
    session_id = state.get("session_id", str(uuid.uuid4()))

    if not optimized_prompt:
        return {
            "messages": [AIMessage(content="No valid question to route.")],
            "memory": memory,
            "session_id": session_id
        }

    routing_prompt = ChatPromptTemplate.from_messages([
        ("system", """You are an expert cybersecurity routing agent. Your task is to analyze the optimized question and determine the appropriate response strategy based on its nature. Choose one of the following options:

        1. search_tavily: Route to this for questions requiring up-to-date, real-time, or specific information, such as recent cybersecurity threats, vulnerabilities (e.g., CVEs), exploits, news, trends, or events.
        2. direct: Route to this for questions that can be answered with general cybersecurity knowledge, including explanations of concepts, definitions, best practices, or theoretical questions.

        Guidelines:
        - Questions about "latest," "recent," or specific events route to search_tavily.
        - Questions about definitions, processes, or general advice route to direct.
        - If ambiguous, prioritize search_tavily for threats or news, and direct for conceptual queries.

        Return a JSON object with a single key 'datasource' and value either 'search_tavily' or 'direct'."""),
        ("human", "{question}")
    ])

    llm_router = ChatGroq(groq_api_key=os.getenv("GROQ_API_KEY"), model="gemma2-9b-it", temperature=0.3)
    structured_llm_router = llm_router.with_structured_output(RouteQuery)
    chain = routing_prompt | structured_llm_router
    decision = chain.invoke({"question": optimized_prompt})
    return {"route_decision": decision.datasource, "memory": memory, "session_id": session_id}

def cyber_expert_response(state: State):
    optimized_prompt = state.get("optimized_prompt", "")
    reference_text = state.get("reference_text", "")
    memory = state.get("memory", ConversationBufferMemory(return_messages=True, max_messages=10))
    session_id = state.get("session_id", str(uuid.uuid4()))

    conversation_history = memory.load_memory_variables({})["history"]
    history_str = "\n".join([f"User: {m.content}" if isinstance(m, HumanMessage) else f"Assistant: {m.content}" for m in conversation_history])

    expert_prompt = ChatPromptTemplate.from_messages([
        ("system", f"""You are a cybersecurity expert. Provide a detailed, accurate, and professional response tailored for a general audience. Use technical terminology, explain it with examples, and focus on clarity and depth. Incorporate insights from the conversation history to maintain context and continuity.
        Conversation History: {history_str}
        Reference Text: {reference_text if reference_text else 'None'}"""),
        ("human", "{question}")
    ])

    llm_expert = ChatGroq(groq_api_key=os.getenv("GROQ_API_KEY"), model="qwen-qwq-32b", temperature=0.3)
    chain = expert_prompt | llm_expert
    response = chain.invoke({"question": optimized_prompt})

    memory.save_context({"input": optimized_prompt}, {"output": response.content})

    return {
        "messages": [AIMessage(content=response.content)],
        "memory": memory,
        "session_id": session_id
    }

def search_tavily(state: State):
    optimized_prompt = state.get("optimized_prompt", "")
    reference_text = state.get("reference_text", "")
    memory = state.get("memory", ConversationBufferMemory(return_messages=True, max_messages=10))
    session_id = state.get("session_id", str(uuid.uuid4()))

    if not optimized_prompt:
        return {
            "messages": [AIMessage(content="No valid question to search.")],
            "memory": memory,
            "session_id": session_id
        }

    query = f"cybersecurity {optimized_prompt}"
    tavily_client = TavilyClient()
    search_results = tavily_client.search(
        query=query,
        search_depth="advanced",
        max_results=10,
        include_answer=True
    )

    results_content = search_results.get("answer", "")
    if not results_content and search_results.get("results"):
        results_content = "\n".join([result["content"] for result in search_results["results"]])

    conversation_history = memory.load_memory_variables({})["history"]
    history_str = "\n".join([f"User: {m.content}" if isinstance(m, HumanMessage) else f"Assistant: {m.content}" for m in conversation_history])

    summary_prompt = ChatPromptTemplate.from_messages([
        ("system", f"""You are a cybersecurity expert. Summarize the provided search results into a concise, informative, and professional response tailored for an expert audience. Combine the search results with your knowledge and conversation history to provide a comprehensive answer. Ensure alignment with the reference text.
        Conversation History: {history_str}
        Reference Text: {reference_text if reference_text else 'None'}"""),
        ("human", "Search Results: {results}\n\nQuestion: {question}")
    ])

    llm_search = ChatGroq(groq_api_key=os.getenv("GROQ_API_KEY"), model="qwen-qwq-32b", temperature=0.3)
    chain = summary_prompt | llm_search
    summarized = chain.invoke({
        "results": results_content,
        "question": optimized_prompt
    })

    response = f"Based on current information, prior discussions, and expert analysis:\n\n{summarized.content}"

    memory.save_context({"input": optimized_prompt}, {"output": summarized.content})

    return {
        "messages": [AIMessage(content=response)],
        "memory": memory,
        "session_id": session_id
    }

@app.route('/chat', methods=['POST'])
def chat():
    try:
        data = request.json
        input_text = data.get('input_text')
        reference_text = data.get('reference_text', "")
        if reference_text == None:
            reference_text = ""
        session_id = data.get('session_id', str(uuid.uuid4()))

        if not input_text:
            return jsonify({"error": "No input text provided"}), 400

        memory = load_session_memory(session_id) or ConversationBufferMemory(return_messages=True, max_messages=20)

        input_state = {
            "messages": [HumanMessage(content=input_text)],
            "reference_text": reference_text,
            "memory": memory,
            "optimized_prompt": "",
            "route_decision": "",
            "session_id": session_id,
            "needs_prompt_engineering": None
        }
        result = graph.invoke(input_state)

        save_session_memory(session_id, result["memory"])

        return jsonify({
            "response": result["messages"][-1].content,
            "session_id": result.get("session_id", session_id)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    os.environ["LANGCHAIN_API_KEY"] = os.environ.get("LANGSMITH_API_KEY")
    os.environ["LANGCHAIN_ENDPOINT"] = "https://api.smith.langchain.com"
    os.environ["LANGCHAIN_TRACING_V2"] = "true"
    os.environ["LANGCHAIN_PROJECT"] = "cyberAdvisor"

    os.environ["TAVILY_API_KEY"] = os.environ.get('TAVILY_API_KEY')

    SESSION_MEMORY_STORE = {}
    graph_builder = StateGraph(State)

    graph_builder.add_node("query_classifier", query_classifier)
    graph_builder.add_node("prompt_engineering", prompt_engineering)
    graph_builder.add_node("routing_agent", routing_agent)
    graph_builder.add_node("cyber_expert_response", cyber_expert_response)
    graph_builder.add_node("search_tavily", search_tavily)

    graph_builder.add_edge(START, "query_classifier")
    graph_builder.add_conditional_edges(
        "query_classifier",
        lambda state: "prompt_engineering" if state.get("needs_prompt_engineering", False) else "routing_agent",
        {
            "prompt_engineering": "prompt_engineering",
            "routing_agent": "routing_agent"
        }
    )
    graph_builder.add_edge("prompt_engineering", "routing_agent")
    graph_builder.add_conditional_edges(
        "routing_agent",
        lambda state: state.get("route_decision", "direct"),
        {
            "search_tavily": "search_tavily",
            "direct": "cyber_expert_response"
        }
    )
    graph_builder.add_edge("cyber_expert_response", END)
    graph_builder.add_edge("search_tavily", END)
    
    graph = graph_builder.compile()
    app.run(host="0.0.0.0", port=5000, debug=True)