#!/usr/bin/env bash
set -e
curl -s -X POST http://localhost:8000/api/v1/scans -H "Content-Type: application/json" -d "{\"repository_url\":\"https://github.com/example/repo\",\"branch\":\"main\"}"
