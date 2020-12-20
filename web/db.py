from redis import Redis
from os import getenv
from dotenv import load_dotenv
from datetime import datetime, timedelta
import bcrypt
import secrets


load_dotenv()
cloud_url = getenv("REDIS_URL")
db = Redis.from_url(cloud_url, decode_responses=True) if cloud_url else Redis(
    host="redis", decode_responses=True)

LOGIN_ATTEMPTS_HISTORY_LENGTH = 10
LOGIN_ATTEMPTS_CHECK_MINUTES = 10
NEXT_LOGIN_SECONDS_PER_ATTEMPT = 5

SESSION_TOKEN_BYTES = 32
SESSION_EXPIRE_SECONDS = 15


# ---------------------------------------------- login, register
def create_user(username, email, password):
    key = "user:" + username + ":profile"
    hashed_password = bcrypt.hashpw(
        password.encode(), bcrypt.gensalt(rounds=10))  # DEBUG, rounds=14

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


def save_login_attempt(username, success, ip):
    key = "user:" + username + ":login-attempts"
    timestamp = int(datetime.now().replace(microsecond=0).timestamp())

    db.lpush(key, f"{timestamp};{int(success)};{ip}")
    db.ltrim(key, 0, LOGIN_ATTEMPTS_HISTORY_LENGTH - 1)


def get_login_attempts(username):
    key = "user:" + username + ":login-attempts"
    attempts = []

    for attempt in db.lrange(key, 0, -1):
        split = attempt.split(";")
        attempts.append(
            {
                "datetime": datetime.fromtimestamp(int(split[0])),
                "success": bool(int(split[1])),
                "ip": split[2]
            }
        )
    return attempts


def count_failed_login_attempts(username):
    attempts = get_login_attempts(username)
    count = 0
    check_delta = timedelta(minutes=LOGIN_ATTEMPTS_CHECK_MINUTES)

    for attempt in attempts:
        delta = datetime.now() - attempt.get("datetime")
        if not attempt.get("success") and delta < check_delta:
            count += 1
        else:
            break
    return count


def seconds_to_next_login(username):
    key = "user:" + username + ":login-attempts"
    if db.llen(key) == 0:
        return 0

    count = count_failed_login_attempts(username)

    last = db.lindex(key, 0).split(";")
    last = datetime.fromtimestamp(int(last[0]))

    elapsed = (datetime.now() - last).seconds
    return max((count-2) * NEXT_LOGIN_SECONDS_PER_ATTEMPT - elapsed, 0)


# ---------------------------------------------- session
def get_session(id_):
    session = db.hgetall("session:" + str(id_))
    username = session.get("username")
    if username:
        set_session_exp(username, SESSION_EXPIRE_SECONDS)
    return session


def set_session(username, key="", value=""):
    user_session_key = "user:" + username + ":session"

    if not db.hget(user_session_key, "id"):
        id_ = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
        print(id_, flush=True)
        db.hset(user_session_key, "id", id_)
        db.hset("session:" + id_, "username", username)
    else:
        id_ = db.hget(user_session_key, "id")

    set_session_exp(username, SESSION_EXPIRE_SECONDS)

    if key and key != username:
        db.hset("session:" + id_, key, value)

    return id_


def set_session_exp(username, seconds):
    session_key = "user:" + str(username) + ":session"
    if db.exists(session_key):
        db.expire("session:" + db.hget(session_key, "id"), seconds)
        db.expire(session_key, seconds)


def clear_session(username):
    set_session_exp(username, 0)
