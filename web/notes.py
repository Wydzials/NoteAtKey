from yaml import safe_load
from datetime import datetime
import secrets
import db
import pytz
import utils


redis = db.redis
config = safe_load(open("config.yaml"))


def create(author, title, content, allowed, public):
    note_id = secrets.token_urlsafe(32)
    while redis.exists(f"note:{note_id}"):
        note_id = secrets.token_urlsafe(32)

    if public:
        redis.sadd("public-notes", note_id)
    else:
        for user in allowed.split(","):
            user = user.strip()
            if db.username_taken(user) and user != author:
                redis.sadd(f"user:{user}:shared", note_id)
                redis.sadd(f"note:{note_id}:readers", user)

    redis.sadd(f"user:{author}:notes", note_id)
    redis.hmset(f"note:{note_id}:content", {
        "author": author,
        "title": title,
        "content": content,
        "datetime": int(datetime.now(pytz.utc).timestamp()),
        "public": int(public)
    })
    return note_id


def delete(note_id):
    if not note_id or not redis.exists(f"note:{note_id}:content"):
        return False

    readers = redis.smembers(f"note:{note_id}:readers")
    for user in readers:
        redis.srem(f"user:{user}:shared", note_id)

    author = redis.hget(f"note:{note_id}:content", "author")

    redis.delete(f"note:{note_id}:readers")
    redis.srem(f"user:{author}:notes", note_id)
    redis.delete(f"note:{note_id}:content")

    redis.srem("public-notes", note_id)

    return True


def get(note_id):
    note = redis.hgetall(f"note:{note_id}:content")
    note["public"] = (note.get("public") == "1")
    note["id"] = note_id

    utc = datetime.fromtimestamp(float(note["datetime"]), tz=pytz.utc)
    local = utils.to_local_time(utc)
    note["date"] = local.date()
    note["time"] = local.time()
    note["datetime"] = local

    if not note.get("public") and redis.exists(f"note:{note_id}:readers"):
        note["readers"] = redis.smembers(f"note:{note_id}:readers")
    return note


def check_readers(readers):
    for user in readers.split(","):
        user = user.strip()
        if len(user) > 0 and not db.username_taken(user):
            return user
    return True


def get_sorted_notes(key):
    notes = []
    for note_id in redis.smembers(key):
        notes.append(get(note_id))
    notes = sorted(notes, key=lambda k: k["datetime"], reverse=True)
    return notes


def get_my_notes(username):
    return get_sorted_notes(f"user:{username}:notes")


def get_public():
    return get_sorted_notes("public-notes")


def get_shared(username):
    return get_sorted_notes(f"user:{username}:shared")
