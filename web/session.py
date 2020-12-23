from yaml import safe_load
import secrets
import db


redis = db.redis
config = safe_load(open("config.yaml"))


def get(id_):
    session = redis.hgetall(f"session:{id_}")
    username = session.get("username")
    if username:
        set_expiration(username, config["session_expire_seconds"])
    return session


def set(username, key="", value=""):
    user_session_key = f"user:{username}:session"

    if not redis.hget(user_session_key, "id"):
        id_ = secrets.token_urlsafe(config["session_token_bytes"])
        print(id_, flush=True)
        redis.hset(user_session_key, "id", id_)
        redis.hset(f"session:{id_}", "username", username)
    else:
        id_ = redis.hget(user_session_key, "id")

    set_expiration(username, config["session_expire_seconds"])

    if key and key != username:
        redis.hset(f"session:{id_}", key, value)

    return id_


def set_expiration(username, seconds):
    session_key = f"user:{username}:session"
    if redis.exists(session_key):
        redis.expire("session:" + redis.hget(session_key, "id"), seconds)
        redis.expire(session_key, seconds)


def clear(username):
    set_expiration(username, 0)
