class ZapParser:
    def parse(self, raw: dict) -> dict:
        return {"tool": "zap", "results": raw}
