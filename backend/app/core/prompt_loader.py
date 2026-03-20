from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

def get_prompt_dir() -> Path:
    env_prompt_dir = os.getenv("PROMPT_DIR", "").strip()
    if env_prompt_dir:
        return Path(env_prompt_dir)
    return Path(__file__).resolve().parent.parent / "prompts"


def resolve_prompt_path(prompt_ref: str | Path) -> Path:
    candidate = Path(prompt_ref)
    prompt_dir = get_prompt_dir()

    if candidate.is_absolute() and candidate.exists():
        return candidate

    if candidate.exists():
        return candidate.resolve()

    direct = prompt_dir / candidate
    if direct.exists():
        return direct

    by_name = prompt_dir / candidate.name
    if candidate.name and by_name.exists():
        return by_name

    raise FileNotFoundError(f"Prompt file not found: {prompt_ref}")


@lru_cache(maxsize=64)
def load_prompt_text(prompt_ref: str | Path) -> str:
    path = resolve_prompt_path(prompt_ref)
    return path.read_text(encoding="utf-8-sig")


def render_prompt_template(prompt_ref: str | Path, replacements: dict[str, str]) -> str:
    prompt_text = load_prompt_text(str(prompt_ref))
    for key, value in replacements.items():
        prompt_text = prompt_text.replace(f"{{{{{key}}}}}", value)
    return prompt_text
