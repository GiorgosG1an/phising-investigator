from fastapi import FastAPI
from backend.api import email_api

app = FastAPI()

@app.get("/")
def read_root():
    return {"message" : "Phishing Investigator API is running"}

app.include_router(email_api.router)