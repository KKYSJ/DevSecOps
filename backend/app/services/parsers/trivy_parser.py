class TrivyParser:
    def parse(self, raw: dict) -> dict:
        return {"tool": "trivy", "results": raw}
