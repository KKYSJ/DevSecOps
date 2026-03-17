from dotenv import load_dotenv
from pathlib import Path
import os

load_dotenv()

APP_ENV = os.getenv("APP_ENV", "local")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
LOCAL_DB_URL = f"sqlite:///{BASE_DIR / 'scan_results.db'}"

DATABASE_URL = os.getenv("DATABASE_URL", LOCAL_DB_URL)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
PROMPT_DIR = os.getenv("PROMPT_DIR", str(BASE_DIR / "app" / "prompts"))