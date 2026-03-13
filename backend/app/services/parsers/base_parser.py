class BaseParser:
    def parse(self, raw: dict) -> dict:
        return {"tool": "base", "results": raw}
