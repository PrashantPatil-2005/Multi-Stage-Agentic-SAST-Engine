"""Utility helpers (fixture)."""

from urllib.parse import urlparse

ALLOWED_HOSTS = {"example.com", "api.example.com"}


def is_safe_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.hostname in ALLOWED_HOSTS


def build_message(template: str, name: str) -> str:
    return template.format(name=name)


class Validators:
    @staticmethod
    def is_safe_host(host: str) -> bool:
        return host in ALLOWED_HOSTS
