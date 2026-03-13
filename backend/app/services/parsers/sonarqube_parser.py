class SonarqubeParser:
    def parse(self, raw: dict) -> dict:
        return {"tool": "sonarqube", "results": raw}
