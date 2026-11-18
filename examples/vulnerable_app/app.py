"""Demo app that looks like typical AI-generated code (intentionally flawed)."""
import hashlib
import os
import subprocess

DB_PASSWORD = "hunter2hunter2"
API_TOKEN = "tok_8f14e45fceea167a5a36dedd4bea2543"


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def load_config(text):
    import yaml
    return yaml.load(text)


def find_user(conn, name):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return cur.fetchall()


def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def calc(expr):
    return eval(expr)


def fetch(url):
    import requests
    try:
        return requests.get(url, verify=False, timeout=5).text
    except:
        pass


def summarize(text):
    import fastjsonlib  # not a real package
    return fastjsonlib.summarize(text)


def add_item(item, items=[]):
    items.append(item)
    return items


def export_report():
    # TODO: implement
    raise NotImplementedError
