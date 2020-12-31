from redis import Redis
from os import getenv
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from yaml import safe_load
import bcrypt
import secrets
import pytz
import utils


load_dotenv()
cloud_url = getenv("REDIS_URL")
redis = Redis.from_url(cloud_url, decode_responses=True) if cloud_url else Redis(
    host="redis", decode_responses=True)

config = safe_load(open("config.yaml"))
if config["debug"]:
    BCRYPT_ROUNDS = 10


def create_user(username, email, password):
    key = f"user:{username}:profile"
    hashed_password = bcrypt.hashpw(
        password.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))

    redis.hset(key, "email", email)
    redis.hset(key, "password", hashed_password)
    redis.sadd("users", username)


def get_user_data(username):
    data = redis.hgetall(f"user:{username}:profile")
    data["username"] = username
    data.pop("password", None)
    data["login_attempts"] = get_login_attempts_localized(username)
    return data


def check_credentials(username, password):
    if not redis.sismember("users", username):
        return False

    hashed_password = redis.hget(f"user:{username}:profile", "password")
    return bcrypt.checkpw(password.encode(), hashed_password.encode())


def username_taken(username):
    return redis.sismember("users", username)


def email_taken(email):
    for user in redis.smembers("users"):
        key = f"user:{user}:profile"
        if email == redis.hget(key, "email"):
            return True
    return False


def save_login_attempt(username, success, ip):
    key = f"user:{username}:login-attempts"
    timestamp = int(datetime.now(pytz.utc).timestamp())

    redis.lpush(key, f"{timestamp};{int(success)};{ip}")
    redis.ltrim(key, 0, config["login_attempts_history_length"] - 1)


def get_login_attempts(username):
    key = f"user:{username}:login-attempts"
    attempts = []

    for attempt in redis.lrange(key, 0, -1):
        split = attempt.split(";")
        attempts.append(
            {
                "datetime": datetime.fromtimestamp(float(split[0]), tz=pytz.utc),
                "success": bool(int(split[1])),
                "ip": split[2]
            }
        )
    return attempts


def get_login_attempts_localized(username):
    attempts = get_login_attempts(username)
    for attempt in attempts:
        localized = utils.to_local_timezone(attempt.get("datetime"))
        attempt["date"] = localized.date()
        attempt["time"] = localized.time()
        attempt.pop("datetime", None)
    return attempts


def count_failed_login_attempts(username):
    attempts = get_login_attempts(username)
    count = 0
    check_delta = timedelta(minutes=config["login_attempts_check_minutes"])

    for attempt in attempts:
        delta = datetime.now(pytz.utc) - attempt.get("datetime")
        if not attempt.get("success") and delta < check_delta:
            count += 1
        else:
            break
    return count


def seconds_to_next_login(username):
    key = f"user:{username}:login-attempts"
    if redis.llen(key) == 0:
        return 0

    count = count_failed_login_attempts(username)

    last = redis.lindex(key, 0).split(";")
    last = datetime.fromtimestamp(int(last[0]), tz=pytz.utc)

    elapsed = (datetime.now(pytz.utc) - last).seconds
    return max((count-2) * config["next_login_seconds_per_attempt"] - elapsed, 0)


def change_password(username, password):
    if not username_taken(username):
        return False

    key = f"user:{username}:profile"
    hashed_password = bcrypt.hashpw(
        password.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))

    redis.hset(key, "password", hashed_password)
    return True


def request_password_reset(email):
    username = 0
    for user in redis.smembers("users"):
        key = f"user:{user}:profile"
        if email == redis.hget(key, "email"):
            username = user
            break

    token = secrets.token_urlsafe(64)
    hashed_token = bcrypt.hashpw(
        token.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))

    key = f"password-reset:{email}"
    redis.hset(key, "username", username)
    redis.hset(key, "token", hashed_token)

    redis.expire(key, 300)
    return token


def reset_password(email, token, password):
    reset = redis.hgetall(f"password-reset:{email}")
    if not reset:
        return False

    username = reset.get("username")
    hashed_token = reset.get("token")

    if bcrypt.checkpw(token.encode(), hashed_token.encode()):
        change_password(username, password)
        redis.delete(f"password-reset:{email}")
        return True
    return False

