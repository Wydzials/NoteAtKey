from redis import Redis
from os import getenv
from dotenv import load_dotenv
import bcrypt


load_dotenv()
cloud_url = getenv("REDIS_URL")
db = Redis.from_url(cloud_url, decode_responses=True) if cloud_url else Redis(
    host="redis", decode_responses=True)


def create_user(username, email, password):
    key = "user:" + username + ":profile"
    hashed_password = bcrypt.hashpw(
        password.encode(), bcrypt.gensalt(rounds=14))

    db.hset(key, "email", email)
    db.hset(key, "password", hashed_password)
    db.sadd("users", username)


def check_password(username, password):
    if not db.sismember("users", username):
        return False

    hashed_password = db.hget("user:" + username + ":profile", "password")
    return bcrypt.checkpw(password.encode(), hashed_password.encode())


def username_taken(username):
    return db.sismember("users", username)
