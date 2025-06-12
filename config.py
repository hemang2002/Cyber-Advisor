# type: ignore
import os
from dotenv import load_dotenv
import random
import redis

load_dotenv()

# API keys and configurations
GROK_API_KEY = os.getenv("GROK_API_KEY")
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY")
SERPER_API = os.getenv("SERPER_API")
DEEP_FAKE_NAME = os.getenv("DEEP_FAKE_NAME")
VIRUSTOTAL_API = os.getenv("VIRUSTOTAL_API")
LANGSMITH_API = os.getenv("LANGSMITH_API_key")
BLOSTER_API_KEY = os.getenv("BLOSTER_API_KEY")

# link and folader
UPLOAD_FOLDER = 'uploads'
DATA_BREACH_URL = 'https://api.xposedornot.com/v1'
VIRUSTOTAL_URL = "https://Www.virustotal.com/api/v3"
XPOSED_API_URL = 'https://api.xposedornot.com/v1'
BLOSTER_URL = "https://developers.bolster.ai/api/neo"

# Deepfake Model name
DEEPFAKE_MODEL_NAME = os.getenv("MODEL_NAME")

# Other parameters of flask
TIMEOUT = 30
SECRET_KEY = str(random.randint(10**13, 10**14 - 1))

# redis
REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_EXPIRE = 450
REDIS_CLIENT = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)

# secret key for session
SECRET_KEY = str(random.randint(10**13, 10**14 - 1))