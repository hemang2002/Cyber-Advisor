FROM python:3.9-slim

WORKDIR /app

COPY chatbot.py .
COPY .env .
COPY requirements_langgraph.txt .

RUN pip install --no-cache-dir -r requirements_langgraph.txt

EXPOSE 80

CMD ["python", "chatbot.py"]