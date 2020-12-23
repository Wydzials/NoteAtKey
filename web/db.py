from redis import Redis
from os import getenv
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
import bcrypt
import secrets
import pytz


DEBUG = True

load_dotenv()
cloud_url = getenv("REDIS_URL")
db = Redis.from_url(cloud_url, decode_responses=True) if cloud_url else Redis(
    host="redis", decode_responses=True)


LOGIN_ATTEMPTS_HISTORY_LENGTH = 10
LOGIN_ATTEMPTS_CHECK_MINUTES = 10
NEXT_LOGIN_SECONDS_PER_ATTEMPT = 5

SESSION_TOKEN_BYTES = 32
SESSION_EXPIRE_SECONDS = 300

BCRYPT_ROUNDS = 14

if DEBUG:
    BCRYPT_ROUNDS = 10


# ---------------------------------------------- login, register
def create_user(username, email, password):
    key = f"user:{username}:profile"
    hashed_password = bcrypt.hashpw(
        password.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))

    db.hset(key, "email", email)
    db.hset(key, "password", hashed_password)
    db.sadd("users", username)


def get_user_data(username):
    data = db.hgetall(f"user:{username}:profile")
    data["username"] = username
    data.pop("password", None)
    data["login_attempts"] = get_login_attempts_localized(username)
    return data


def check_credentials(username, password):
    if not db.sismember("users", username):
        return False

    hashed_password = db.hget(f"user:{username}:profile", "password")
    return bcrypt.checkpw(password.encode(), hashed_password.encode())


def username_taken(username):
    return db.sismember("users", username)


def email_taken(email):
    for user in db.smembers("users"):
        key = f"user:{user}:profile"
        if email == db.hget(key, "email"):
            return True
    return False


def save_login_attempt(username, success, ip):
    key = f"user:{username}:login-attempts"
    timestamp = int(datetime.now(pytz.utc).timestamp())

    db.lpush(key, f"{timestamp};{int(success)};{ip}")
    db.ltrim(key, 0, LOGIN_ATTEMPTS_HISTORY_LENGTH - 1)


def get_login_attempts(username):
    key = f"user:{username}:login-attempts"
    attempts = []

    for attempt in db.lrange(key, 0, -1):
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
        localized = to_local_timezone(attempt.get("datetime"))
        attempt["date"] = localized.date()
        attempt["time"] = localized.time()
        attempt.pop("datetime", None)
    return attempts


def count_failed_login_attempts(username):
    attempts = get_login_attempts(username)
    count = 0
    check_delta = timedelta(minutes=LOGIN_ATTEMPTS_CHECK_MINUTES)

    for attempt in attempts:
        delta = datetime.now(pytz.utc) - attempt.get("datetime")
        if not attempt.get("success") and delta < check_delta:
            count += 1
        else:
            break
    return count


def seconds_to_next_login(username):
    key = f"user:{username}:login-attempts"
    if db.llen(key) == 0:
        return 0

    count = count_failed_login_attempts(username)

    last = db.lindex(key, 0).split(";")
    last = datetime.fromtimestamp(int(last[0]), tz=pytz.utc)

    elapsed = (datetime.now(pytz.utc) - last).seconds
    return max((count-2) * NEXT_LOGIN_SECONDS_PER_ATTEMPT - elapsed, 0)


def change_password(username, password):
    if not username_taken(username):
        return False

    key = f"user:{username}:profile"
    hashed_password = bcrypt.hashpw(
        password.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))

    db.hset(key, "password", hashed_password)
    return True


def request_password_reset(email):
    username = 0
    for user in db.smembers("users"):
        key = f"user:{user}:profile"
        if email == db.hget(key, "email"):
            username = user
            break

    token = secrets.token_urlsafe(64)
    hashed_token = bcrypt.hashpw(
        token.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))

    key = f"password-reset:{email}"
    db.hset(key, "username", username)
    db.hset(key, "token", hashed_token)

    db.expire(key, 300)
    return token


def reset_password(email, token, password):
    reset = db.hgetall(f"password-reset:{email}")
    if not reset:
        return False

    username = reset.get("username")
    hashed_token = reset.get("token")

    if bcrypt.checkpw(token.encode(), hashed_token.encode()):
        change_password(username, password)
        db.delete(f"password-reset:{email}")
        return True
    return False


def to_local_timezone(utc):
    local = pytz.timezone("Europe/Warsaw")
    local_dt = utc.replace(tzinfo=pytz.utc).astimezone(local)
    return local.normalize(local_dt)


# ---------------------------------------------- session
def get_session(id_):
    session = db.hgetall(f"session:{id_}")
    username = session.get("username")
    if username:
        set_session_exp(username, SESSION_EXPIRE_SECONDS)
    return session


def set_session(username, key="", value=""):
    user_session_key = f"user:{username}:session"

    if not db.hget(user_session_key, "id"):
        id_ = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
        print(id_, flush=True)
        db.hset(user_session_key, "id", id_)
        db.hset(f"session:{id_}", "username", username)
    else:
        id_ = db.hget(user_session_key, "id")

    set_session_exp(username, SESSION_EXPIRE_SECONDS)

    if key and key != username:
        db.hset(f"session:{id_}", key, value)

    return id_


def set_session_exp(username, seconds):
    session_key = f"user:{username}:session"
    if db.exists(session_key):
        db.expire("session:" + db.hget(session_key, "id"), seconds)
        db.expire(session_key, seconds)


def clear_session(username):
    set_session_exp(username, 0)


# ---------------------------------------------- notes
def create_note(author, title, content, allowed):
    note_id = secrets.token_urlsafe(32)

    for user in allowed.split(","):
        user = user.strip()
        if username_taken(user) and user != author:
            db.sadd(f"user:{user}:can_read", note_id)
            db.sadd(f"note:{note_id}:readers", user)

    db.sadd(f"user:{author}:notes", note_id)
    db.hmset(f"note:{note_id}:content", {
        "author": author,
        "title": title,
        "content": content,
    })
    return note_id


def delete_note(note_id):
    if not note_id or not db.exists(f"note:{note_id}:content"):
        return False

    readers = db.smembers(f"note:{note_id}:readers")
    for user in readers:
        db.srem(f"user:{user}:can_read", note_id)

    author = db.hget(f"note:{note_id}:content", "author")

    db.delete(f"note:{note_id}:readers")
    db.srem(f"user:{author}:notes", note_id)
    db.delete(f"note:{note_id}:content")

    return True
