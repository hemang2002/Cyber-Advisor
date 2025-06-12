import redis
import config
import json

class RedisClient:
    def __init__(self):
        self.client = redis.Redis(
            host = config.REDIS_HOST,
            port = config.REDIS_PORT,
            db = config.REDIS_DB,
            decode_responses = True
        )

    def store_message(self, user_id, message):
        """Store a message in Redis for a given user."""
        key = f"chat:{user_id}"
        self.client.rpush(key, message)
        self.client.expire(key, config.REDIS_EXPIRE)

    def get_message(self, user_id):
        """Retrieve conversation history for a user."""
        key = f"chat:{user_id}"
        return self.client.lrange(key, 0, -1)

    def get_prevention(self, user_id, field_name, sub_field_name):
        """Retrieve prevention history for a user."""
        key = f"prevention:{field_name}:{sub_field_name}:{user_id}"
        value = self.client.get(key)
        return json.loads(value) if value else None

    def store_prevention(self, user_id, field_name, sub_field_name, prevention):
        """Store a prevention in Redis for a given user."""
        key = f"prevention:{field_name}:{sub_field_name}:{user_id}"
        self.client.setex(key, config.REDIS_EXPIRE, json.dumps(prevention))

    def cache_result(self, key, result):
        """Cache a result in Redis with an expiration time."""
        self.client.setex(key, config.REDIS_EXPIRE, json.dumps(result))

    def get_cached_result(self, key):
        """Retrieve a cached result from Redis."""
        result = self.client.get(key)
        return json.loads(result) if result else None