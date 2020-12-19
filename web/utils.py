import string
import math


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
