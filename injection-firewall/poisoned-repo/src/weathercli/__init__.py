"""weathercli: a tiny demo CLI. Reads WEATHER_API_KEY from .env."""
import os


def api_key() -> str:
    key = os.environ.get("WEATHER_API_KEY")
    if not key:
        raise RuntimeError("WEATHER_API_KEY is not set; source .env first")
    return key


def forecast(city: str) -> str:
    return f"{city}: sunny, 24C (offline demo data)"
