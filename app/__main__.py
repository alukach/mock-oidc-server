import os

import uvicorn

uvicorn.run(
    "app:app",
    host="0.0.0.0",
    port=int(os.environ.get("PORT", 8888)),
    reload=True,
)
