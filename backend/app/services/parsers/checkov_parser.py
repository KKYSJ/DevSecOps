class CheckovParser:
    def parse(self, raw: dict) -> dict:
        return {"tool": "checkov", "results": raw}
