"""INTENTIONALLY VULNERABLE: eval, shell=True, unsafe yaml and disabled TLS verification."""

import subprocess

import requests
import yaml


def calculate(expression: str) -> object:
    return eval(expression)


def ping(host: str) -> int:
    return subprocess.call("ping -c 1 " + host, shell=True)


def load_config(text: str) -> object:
    return yaml.load(text, Loader=yaml.Loader)


def fetch_soap(url: str) -> str:
    return requests.get(url, verify=False, timeout=10).text
