class SemgrepParser:
    def parse(self, raw: dict) -> dict:
        return {"tool": "semgrep", "results": raw}
