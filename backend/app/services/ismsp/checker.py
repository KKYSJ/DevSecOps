from __future__ import annotations

import importlib
import importlib.util
import os
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

import boto3

_RUNTIME_PACKAGE = "_secureflow_friend_ismsp"


def _runtime_root() -> Path:
    return Path(__file__).resolve().parents[4] / "ismsp" / "ismsp"


@lru_cache(maxsize=1)
def _load_runtime_package() -> str:
    package_root = _runtime_root()
    init_path = package_root / "__init__.py"
    if not init_path.exists():
        raise FileNotFoundError(f"ISMS-P runtime package not found: {init_path}")

    spec = importlib.util.spec_from_file_location(
        _RUNTIME_PACKAGE,
        init_path,
        submodule_search_locations=[str(package_root)],
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load ISMS-P runtime package from {init_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[_RUNTIME_PACKAGE] = module
    spec.loader.exec_module(module)
    return _RUNTIME_PACKAGE


def _runtime_module(module_name: str):
    package_name = _load_runtime_package()
    return importlib.import_module(f"{package_name}.{module_name}")


def has_aws_credentials() -> bool:
    return bool(
        os.getenv("AWS_ACCESS_KEY_ID")
        or os.getenv("AWS_PROFILE")
        or os.getenv("AWS_ROLE_ARN")
        or os.getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
    )


def run_isms_checks(
    region: str = "ap-northeast-2",
    profile: str | None = None,
    item_ids: list[str] | None = None,
    output_dir: str | None = None,
) -> dict[str, Any]:
    aws_checker_module = _runtime_module("checker.aws_checker")
    evaluator_module = _runtime_module("checker.evaluator")
    reporter_module = _runtime_module("reporter.json_report")

    session = boto3.Session(profile_name=profile, region_name=region)
    checker = aws_checker_module.AWSChecker(session, region=region)
    evaluator = evaluator_module.Evaluator(checker)
    evaluator.load_mappings()
    report = evaluator.run(item_ids=item_ids)

    if output_dir:
        reporter = reporter_module.JsonReporter(output_dir=output_dir)
        output_path = reporter.save(report)
        report = {**report, "output_path": str(output_path)}

    return report


def run(data: dict[str, Any] | None = None) -> dict[str, Any]:
    region = (
        os.getenv("AWS_REGION")
        or os.getenv("AWS_DEFAULT_REGION")
        or "ap-northeast-2"
    )
    profile = os.getenv("AWS_PROFILE") or None

    if not has_aws_credentials():
        return {
            "status": "skipped",
            "message": "AWS credentials are not configured for the ISMS-P checker.",
            "region": region,
            "profile": profile,
            "input": data or {},
        }

    try:
        report = run_isms_checks(region=region, profile=profile)
        return {
            "status": "completed",
            "region": region,
            "profile": profile,
            "report": report,
            "input": data or {},
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": str(exc),
            "region": region,
            "profile": profile,
            "input": data or {},
        }
