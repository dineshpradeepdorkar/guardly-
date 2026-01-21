from fastapi import FastAPI, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pymongo import MongoClient
from dotenv import load_dotenv
import bcrypt
import yagmail
import os
import secrets
import string
from datetime import datetime, timedelta

# =============================
# ENV LOAD + DEBUG CHECK
# =============================
load_dotenv()

EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
RESET_BASE_URL = os.getenv("RESET_BASE_URL")
TOKEN_EXPIRY_MINUTES = int(os.getenv("TOKEN_EXPIRY_MINUTES", 5))

print("\n=== ENV DEBUG ===")
print("EMAIL_SENDER =", EMAIL_SENDER)
print("EMAIL_PASSWORD =", "SET" if EMAIL_PASSWORD else "MISSING")
print("RESET_BASE_URL =", RESET_BASE_URL)
print("=================\n")

app = FastAPI()

# =============================
# CORS MIDDLEWARE
# =============================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================
# MONGO
# =============================
client = MongoClient("mongodb://localhost:27017")
db = client["login_db"]
users = db["users"]

# =============================
# FORGOT PASSWORD
# =============================
@app.post("/forgot")
async def forgot(email: str = Form(...)):
    user = users.find_one({"email": email})
    if not user:
        return {"success": True}  # do not reveal existence for security

    token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(48))
    expiry = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRY_MINUTES)

    users.update_one(
        {"email": email},
        {"$set": {"reset_token": token, "reset_expiry": expiry}}
    )

    reset_link = f"{RESET_BASE_URL}?token={token}"

    # SMTP CONNECT DEBUG
    try:
        yag = yagmail.SMTP(EMAIL_SENDER, EMAIL_PASSWORD)
        print("SMTP CONNECT OK")
    except Exception as e:
        print("\nSMTP CONNECT ERROR:", e, "\n")
        return {"success": False, "error": str(e)}

    html_content = f"""
    <h2 style="font-family:Poppins;">Guardly Password Reset</h2>
    <p style="font-family:Poppins;">You requested to reset your password.</p>
    <p style="font-family:Poppins;">Click the button below to reset:</p>
    <a href="{reset_link}" style="
        display:inline-block;
        background:#13b7ff;
        color:white;
        padding:10px 18px;
        text-decoration:none;
        border-radius:6px;
        font-family:Poppins;
        margin-top:10px;">
        Reset Password
    </a>
    <p style="font-family:Poppins;margin-top:12px;">
        Link expires in {TOKEN_EXPIRY_MINUTES} minutes.
    </p>
    """

    # SMTP SEND DEBUG
    try:
        yag.send(to=email, subject="Guardly - Reset Password", contents=html_content)
        print("SMTP SEND OK →", email)
    except Exception as e:
        print("\nSMTP SEND ERROR:", e, "\n")
        return {"success": False, "error": str(e)}

    return {"success": True}


# =============================
# RESET PASSWORD
# =============================
@app.post("/reset-password")
async def reset_password(token: str = Form(...), password: str = Form(...)):
    user = users.find_one({"reset_token": token})
    if not user:
        return {"success": False, "message": "Invalid token"}

    if user["reset_expiry"] < datetime.utcnow():
        return {"success": False, "message": "Token expired"}

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    users.update_one(
        {"reset_token": token},
        {"$set": {"password": hashed}, "$unset": {"reset_token": "", "reset_expiry": ""}}
    )

    return {"success": True}


# =============================
# REGISTER
# =============================
@app.post("/register")
async def register(fullname: str = Form(...), phone: str = Form(...), email: str = Form(...), password: str = Form(...)):
    user = users.find_one({"email": email})
    if user:
        return JSONResponse({"success": False, "message": "User already exists"})

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    users.insert_one({"fullname": fullname, "phone": phone, "email": email, "password": hashed})
    return JSONResponse({"success": True})


# =============================
# LOGIN
# =============================
@app.post("/login")
async def login(email: str = Form(...), password: str = Form(...)):
    user = users.find_one({"email": email})
    if not user:
        return JSONResponse({"success": False, "message": "User not found"})

    if bcrypt.checkpw(password.encode(), user["password"]):
        return JSONResponse({"success": True})
    else:
        return JSONResponse({"success": False, "message": "Invalid password"})
