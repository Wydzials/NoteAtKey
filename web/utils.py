from flask import request
from yaml import safe_load
import string
import math
import pytz
import sys


config = safe_load(open("config.yaml"))


def password_bits(password):
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = "!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"

    groups = [lowercase, uppercase, digits, special]

    for c in password:
        found = False
        for group in groups:
            if c in group:
                found = True
        if not found:
            raise ValueError("Invalid character: " + c)

    sum = 0
    for group in groups:
        for character in group:
            if character in password:
                sum += len(group)
                break
    combinations = pow(sum, len(password)) or 1
    return(math.log2(combinations))


def check_password(password1, password2):
    errors = []

    if not password1 or not password2:
        errors.append("Hasło nie może być puste.")

    if password1 != password2:
        errors.append("Hasła są różne.")

    if len(password1) > 50:
        errors.append("Hasło może mieć maksymalnie 50 znaków.")

    try:
        BITS_REQUIRED = config["min_password_bits"]
        bits = round(password_bits(password1))
        if bits < BITS_REQUIRED:
            errors.append(
                f"Hasło jest zbyt słabe ({bits} bitów, wymagane minimum {BITS_REQUIRED} bitów).")
    except ValueError:
        errors.append("Nieprawidłowy znak w haśle. Dozwolone znaki to: \
            małe i duże litery, cyfry, znaki specjalne: \
            !\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~.")

    return errors


def get_ip(request):
    if not request.environ.get("HTTP_X_FORWARDED_FOR"):
        return request.environ["REMOTE_ADDR"]
    else:
        return request.environ["HTTP_X_FORWARDED_FOR"]


def check_config():
    config = safe_load(open("config.yaml"))
    keys = [
        "debug",
        "login_attempts_history_length",
        "login_attempts_check_minutes",
        "next_login_seconds_per_attempt",
        "bcrypt_rounds",
        "min_password_bits",

        "session_token_bytes",
        "session_expire_seconds",

        "max_note_lines",
        "max_note_length",
        "max_note_title_length",
        "max_note_readers_length"
    ]

    for key in keys:
        if config.get(key) == None:
            print("No argument in config.yaml: " + key + ".", flush=True)
            sys.exit(4)
    return True


def to_local_time(utc):
    local = pytz.timezone("Europe/Warsaw")
    local_dt = utc.replace(tzinfo=pytz.utc).astimezone(local)
    return local.normalize(local_dt)
