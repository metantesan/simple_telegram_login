import fastapi
from .auth import auth_router

app = fastapi.FastAPI()


app.include_router(auth_router)
@app.get("/")
async def index():
    return {"message": "Hello World!"}
