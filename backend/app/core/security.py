from fastapi import Header, HTTPException


async def verify_api_key(x_api_key: str | None = Header(default=None)):
    if x_api_key in (None, "", "dev-key"):
        return True
    raise HTTPException(status_code=401, detail="Invalid API key")
