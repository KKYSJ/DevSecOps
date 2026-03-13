class TfsecParser:
    def parse(self, raw: dict) -> dict:
        return {"tool": "tfsec", "results": raw}
