import json
from engine.normalizer.normalize import normalize

if __name__ == "__main__":
    print(json.dumps(normalize({"tool": "example"}), indent=2))
