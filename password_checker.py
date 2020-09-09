#!/usr/bin/env python3
"""Checks to see if a password has been exposed in a data breach using the
Have I Been Pwned API.

Usage: python3 password_checker.py [password]

Reminder: Your terminal command history may be logged in plaintext.
"""

import hashlib
import sys

import requests


def request_api_data(query):
    """Returns API request data."""
    url = 'https://api.pwnedpasswords.com/range/' + query
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}. Check API and retry.')
    return res


def get_password_leaks_count(hashes, hashes_to_check):
    """Returns count specified for matching hash."""
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hashes_to_check:
            return count
    return 0


def pwned_api_check(password):
    """Compares API response to first 5 characters of SHA1-hashed password with
    subsequent characters (k-anonymity).
    """
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_5_chars, tail = sha1_password[:5], sha1_password[5:]
    response = request_api_data(first_5_chars)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'Password: "{password}" found {count} times.')
        else:
            print(f'Password: "{password}" not found.')
    return 'Done'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
