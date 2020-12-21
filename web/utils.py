import string
import math
from flask import request
import pytz


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
        BITS_REQUIRED = 1  # DEBUG
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
