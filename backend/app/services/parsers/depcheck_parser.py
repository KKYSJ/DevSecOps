class DepcheckParser:
    def parse(self, raw: dict) -> dict:
        return {"tool": "depcheck", "results": raw}
