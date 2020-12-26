from yaml import safe_load
import secrets
import db


redis = db.redis
config = safe_load(open("config.yaml"))


def create(author, title, content, allowed):
    note_id = secrets.token_urlsafe(32)

    for user in allowed.split(","):
        user = user.strip()
        if db.username_taken(user) and user != author:
            redis.sadd(f"user:{user}:can_read", note_id)
            redis.sadd(f"note:{note_id}:readers", user)

    redis.sadd(f"user:{author}:notes", note_id)
    redis.hmset(f"note:{note_id}:content", {
        "author": author,
        "title": title,
        "content": content,
    })
    return note_id


def delete(note_id):
    if not note_id or not redis.exists(f"note:{note_id}:content"):
        return False

    readers = redis.smembers(f"note:{note_id}:readers")
    for user in readers:
        redis.srem(f"user:{user}:can_read", note_id)

    author = redis.hget(f"note:{note_id}:content", "author")

    redis.delete(f"note:{note_id}:readers")
    redis.srem(f"user:{author}:notes", note_id)
    redis.delete(f"note:{note_id}:content")

    return True


def get(note_id):
    note = redis.hgetall(f"note:{note_id}:content")
    note["id"] = note_id
    note["readers"] = redis.smembers(f"note:{note_id}:readers")
    return note


def get_my_notes(username):
    notes = []
    for note_id in redis.smembers(f"user:{username}:notes"):
        notes.append(get(note_id))
    return notes
