# Deliberately vulnerable sample — used by the test suite and as a demo target.
# Everything in this file is *meant* to be flagged. Do not copy it.
import os
import pickle
import hashlib
import random
import subprocess

DEBUG = True
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
db_password = "sup3rs3cr3tp@ss"
api_key = "your_api_key_here"          # placeholder — must NOT be flagged


def run(cmd):
    os.system(cmd)                      # CODE_OS_SYSTEM
    subprocess.run(cmd, shell=True)     # CODE_SUBPROCESS_SHELL


def load(blob):
    return pickle.loads(blob)           # CODE_PICKLE


def hash_pw(pw):
    return hashlib.md5(pw.encode()).hexdigest()   # CODE_MD5


def weak_token():
    token = random.random()             # CODE_WEAK_RANDOM
    return token


def find(cur, name):
    cur.execute("SELECT * FROM users WHERE name='" + name + "'")   # CODE_SQL_CONCAT
