from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
import asyncpg
from datetime import datetime, timedelta
from typing import List, Dict
import os
from dotenv import load_dotenv
from contextlib import asynccontextmanager
import logging
import asyncio
import uvicorn

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variables
db_pool = None
connections: Dict[str, WebSocket] = {}

# Load environment variables
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY", "your-secure-secret-key-1234567890")
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000,https://your-frontend-service.onrender.com").split(",")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

if not DATABASE_URL:
    logger.error("DATABASE_URL not set in .env")
    raise ValueError("DATABASE_URL not set in .env")

if not SECRET_KEY or SECRET_KEY == "your-secure-secret-key-1234567890":
    logger.warning("Using default SECRET_KEY. Set a secure SECRET_KEY in .env for production.")

# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_pool
    try:
        db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=5, max_size=20)
        async with db_pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS friends (
                    user_id INTEGER REFERENCES users(id),
                    friend_id INTEGER REFERENCES users(id),
                    PRIMARY KEY (user_id, friend_id)
                );
                CREATE TABLE IF NOT EXISTS friend_requests (
                    id SERIAL PRIMARY KEY,
                    sender_id INTEGER REFERENCES users(id),
                    recipient_id INTEGER REFERENCES users(id),
                    status VARCHAR(10) DEFAULT 'pending',
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (sender_id, recipient_id)
                );
                CREATE TABLE IF NOT EXISTS messages (
                    id SERIAL PRIMARY KEY,
                    sender_id INTEGER REFERENCES users(id),
                    recipient_id INTEGER REFERENCES users(id),
                    content TEXT NOT NULL,
                    type VARCHAR(20) NOT NULL DEFAULT 'text',
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_read BOOLEAN DEFAULT FALSE
                );
                CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
                CREATE INDEX IF NOT EXISTS idx_friend_requests_status ON friend_requests(status);
            """)
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise
    yield
    if db_pool:
        await db_pool.close()
        logger.info("Database connection closed")

# Initialize FastAPI app
app = FastAPI(lifespan=lifespan)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000",
        "https://chitchat-client-nato.onrender.com",  # Your frontend URL
        "https://chitchat-server-emw5.onrender.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Root endpoint
@app.get("/")
async def root():
    return {"message": "ChitChat Backend is Live!"}

# Pydantic models
class UserCreate(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class MessageCreate(BaseModel):
    recipient_username: str
    content: str
    type: str = "text"

class MessageUpdate(BaseModel):
    content: str

class FriendRequest(BaseModel):
    recipient_username: str

class FriendRequestResponse(BaseModel):
    request_id: int
    accept: bool

class MessageOut(BaseModel):
    id: int
    sender_username: str
    recipient_username: str
    content: str
    type: str
    timestamp: str
    is_read: bool

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat() + "Z"}

class Conversation(BaseModel):
    username: str
    messages: List[MessageOut]

class FriendRequestOut(BaseModel):
    id: int
    sender_username: str
    recipient_username: str
    status: str
    timestamp: str

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat() + "Z"}

class UserOut(BaseModel):
    id: int
    username: str

# Token creation
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Get current user
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        async with db_pool.acquire() as conn:
            user = await conn.fetchrow("SELECT id, username FROM users WHERE id = $1", int(user_id))
            if not user:
                raise HTTPException(status_code=401, detail="User not found")
        return {"id": user["id"], "username": user["username"]}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Register endpoint
@app.post("/register")
async def register(user: UserCreate):
    logger.info(f"Register attempt for username: {user.username}")
    async with db_pool.acquire() as conn:
        try:
            hashed_password = pwd_context.hash(user.password)
            await conn.execute(
                "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
                user.username, hashed_password
            )
            logger.info(f"User registered successfully: {user.username}")
            return {"msg": "User created successfully"}
        except asyncpg.exceptions.UniqueViolationError:
            logger.warning(f"Username already exists: {user.username}")
            raise HTTPException(status_code=400, detail="Username already exists")
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            raise HTTPException(status_code=500, detail="Internal server error")

# Login endpoint
@app.post("/login")
async def login(form_data: LoginRequest):
    logger.info(f"Login attempt for username: {form_data.username}")
    async with db_pool.acquire() as conn:
        try:
            user = await conn.fetchrow(
                "SELECT id, username, password_hash FROM users WHERE username = $1",
                form_data.username
            )
            if not user or not pwd_context.verify(form_data.password, user["password_hash"]):
                logger.warning(f"Login failed: Invalid credentials for '{form_data.username}'")
                raise HTTPException(status_code=401, detail="Invalid credentials")
            token = create_access_token({"sub": str(user["id"])})
            logger.info(f"User logged in successfully: {user['username']}")
            return {"access_token": token, "token_type": "bearer"}
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            raise HTTPException(status_code=500, detail="Internal server error")

# Get current user
@app.get("/users/me")
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return {"username": current_user["username"]}

# Search users
@app.get("/users", response_model=List[UserOut])
async def search_users(search: str = "", current_user: dict = Depends(get_current_user)):
    async with db_pool.acquire() as conn:
        if search:
            users = await conn.fetch(
                "SELECT id, username FROM users WHERE username ILIKE $1 AND id != $2",
                f"%{search}%", current_user["id"]
            )
        else:
            users = await conn.fetch("SELECT id, username FROM users WHERE id != $1", current_user["id"])
        logger.debug(f"Search returned {len(users)} users")
        return [{"id": u["id"], "username": u["username"]} for u in users]

# Get suggested users
@app.get("/users/suggestions", response_model=List[UserOut])
async def get_suggested_users(current_user: dict = Depends(get_current_user)):
    async with db_pool.acquire() as conn:
        suggestions = await conn.fetch(
            """
            SELECT id, username
            FROM users u
            WHERE u.id != $1
            AND NOT EXISTS (
                SELECT 1 FROM friends f 
                WHERE (f.user_id = u.id AND f.friend_id = $1) 
                OR (f.user_id = $1 AND f.friend_id = u.id)
            )
            AND NOT EXISTS (
                SELECT 1 FROM friend_requests fr 
                WHERE (fr.sender_id = u.id AND fr.recipient_id = $1 AND fr.status = 'pending')
                OR (fr.sender_id = $1 AND fr.recipient_id = u.id AND fr.status = 'pending')
            )
            ORDER BY RANDOM()
            LIMIT 10
            """, current_user["id"]
        )
        logger.debug(f"Fetched {len(suggestions)} suggested users")
        return [{"id": s["id"], "username": s["username"]} for s in suggestions]

# Helper: Fetch message row
async def fetch_message_row(conn, query, *args):
    row = await conn.fetchrow(query, *args)
    if row:
        return dict(row) | {"timestamp": row["timestamp"].isoformat() + "Z"}
    return None

# Helper: Check if users are friends
async def are_friends(conn, user_id: int, friend_id: int):
    result = await conn.fetchrow(
        "SELECT 1 FROM friends WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)",
        user_id, friend_id
    )
    return bool(result)

# Send friend request
@app.post("/friend-request")
async def send_friend_request(request: FriendRequest, current_user: dict = Depends(get_current_user)):
    async with db_pool.acquire() as conn:
        recipient = await conn.fetchrow(
            "SELECT id, username FROM users WHERE username = $1", request.recipient_username
        )
        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient not found")
        if recipient["id"] == current_user["id"]:
            raise HTTPException(status_code=400, detail="Cannot send friend request to yourself")
        if await are_friends(conn, current_user["id"], recipient["id"]):
            raise HTTPException(status_code=400, detail="Already friends")
        existing_request = await conn.fetchrow(
            "SELECT id FROM friend_requests WHERE sender_id = $1 AND recipient_id = $2 AND status = 'pending'",
            current_user["id"], recipient["id"]
        )
        if existing_request:
            raise HTTPException(status_code=400, detail="Friend request already sent")
        msg = await fetch_message_row(
            conn,
            "INSERT INTO messages (sender_id, recipient_id, content, type) VALUES ($1, $2, $3, $4) RETURNING id, sender_id, recipient_id, content, type, timestamp, is_read",
            current_user["id"], recipient["id"], f"Friend request from {current_user['username']}", "friend_request"
        )
        request_data = await conn.fetchrow(
            "INSERT INTO friend_requests (sender_id, recipient_id) VALUES ($1, $2) RETURNING id, sender_id, recipient_id, status, timestamp",
            current_user["id"], recipient["id"]
        )
        message_data = {
            "id": msg["id"],
            "sender_username": current_user["username"],
            "recipient_username": recipient["username"],
            "content": msg["content"],
            "type": msg["type"],
            "timestamp": msg["timestamp"],
            "is_read": msg["is_read"]
        }
        if recipient["username"] in connections:
            await connections[recipient["username"]].send_json({"type": "message", "data": message_data})
        logger.info(f"Friend request sent from {current_user['username']} to {request.recipient_username}")
        return {"msg": "Friend request sent", "request_id": request_data["id"]}

# Respond to friend request
@app.post("/friend-request/respond")
async def respond_friend_request(response: FriendRequestResponse, current_user: dict = Depends(get_current_user)):
    async with db_pool.acquire() as conn:
        request = await conn.fetchrow(
            """
            SELECT fr.id, fr.sender_id, fr.recipient_id, fr.status, u1.username AS sender_username, u2.username AS recipient_username
            FROM friend_requests fr
            JOIN users u1 ON fr.sender_id = u1.id
            JOIN users u2 ON fr.recipient_id = u2.id
            WHERE fr.id = $1 AND fr.recipient_id = $2
            """,
            response.request_id, current_user["id"]
        )
        if not request or request["status"] != "pending":
            raise HTTPException(status_code=404, detail="Friend request not found or already processed")
        try:
            if response.accept:
                await conn.execute(
                    """
                    INSERT INTO friends (user_id, friend_id) VALUES ($1, $2), ($2, $1)
                    ON CONFLICT DO NOTHING
                    """,
                    current_user["id"], request["sender_id"]
                )
                await conn.execute(
                    "UPDATE friend_requests SET status = $1 WHERE id = $2",
                    "accepted", response.request_id
                )
                friend_data = {"username": current_user["username"]}
                if request["sender_username"] in connections:
                    await connections[request["sender_username"]].send_json(
                        {"type": "friend_accepted", "data": friend_data}
                    )
                logger.info(f"Friend request accepted: {request['sender_username']} and {current_user['username']}")
            else:
                await conn.execute(
                    "UPDATE friend_requests SET status = $1 WHERE id = $2",
                    "rejected", response.request_id
                )
                logger.info(f"Friend request rejected: {request['sender_username']} by {current_user['username']}")
            return {"msg": "Friend request response processed"}
        except Exception as e:
            logger.error(f"Error processing friend request response: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to process friend request response")

# Get friend requests
@app.get("/friend-requests", response_model=List[FriendRequestOut])
async def get_friend_requests(current_user: dict = Depends(get_current_user)):
    async with db_pool.acquire() as conn:
        requests = await conn.fetch(
            """
            SELECT fr.id, u1.username AS sender_username, u2.username AS recipient_username, fr.status, fr.timestamp
            FROM friend_requests fr
            JOIN users u1 ON fr.sender_id = u1.id
            JOIN users u2 ON fr.recipient_id = u2.id
            WHERE fr.recipient_id = $1 OR fr.sender_id = $1
            ORDER BY fr.timestamp DESC
            """,
            current_user["id"]
        )
        logger.debug(f"Fetched {len(requests)} friend requests for {current_user['username']}")
        return [
            {
                "id": r["id"],
                "sender_username": r["sender_username"],
                "recipient_username": r["recipient_username"],
                "status": r["status"],
                "timestamp": r["timestamp"].isoformat() + "Z"
            }
            for r in requests
        ]

# Send message
@app.post("/messages")
async def send_message(message: MessageCreate, current_user: dict = Depends(get_current_user)):
    async with db_pool.acquire() as conn:
        recipient = await conn.fetchrow(
            "SELECT id, username FROM users WHERE username = $1", message.recipient_username
        )
        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient not found")
        if not await are_friends(conn, current_user["id"], recipient["id"]) and message.type != "friend_request":
            raise HTTPException(status_code=403, detail="Not friends with recipient")
        msg = await fetch_message_row(
            conn,
            """
            INSERT INTO messages (sender_id, recipient_id, content, type)
            VALUES ($1, $2, $3, $4)
            RETURNING id, sender_id, recipient_id, content, type, timestamp, is_read
            """,
            current_user["id"], recipient["id"], message.content, message.type
        )
        message_data = {
            "id": msg["id"],
            "sender_username": current_user["username"],
            "recipient_username": recipient["username"],
            "content": msg["content"],
            "type": msg["type"],
            "timestamp": msg["timestamp"],
            "is_read": msg["is_read"]
        }
        if recipient["username"] in connections:
            await connections[recipient["username"]].send_json({"type": "message", "data": message_data})
        if current_user["username"] in connections:
            await connections[current_user["username"]].send_json({"type": "message", "data": message_data})
        logger.info(f"Message sent from {current_user['username']} to {recipient['username']} (type: {msg['type']})")
        return {"msg": "Message sent"}

# Edit message
@app.put("/messages/{message_id}")
async def edit_message(message_id: int, update: MessageUpdate, current_user: dict = Depends(get_current_user)):
    async with db_pool.acquire() as conn:
        msg = await conn.fetchrow(
            """
            SELECT id, sender_id, recipient_id
            FROM messages
            WHERE id = $1 AND sender_id = $2
            """,
            message_id, current_user["id"]
        )
        if not msg:
            raise HTTPException(status_code=404, detail="Message not found or not authorized")
        recipient = await conn.fetchrow(
            "SELECT username FROM users WHERE id = $1", msg["recipient_id"]
        )
        await conn.execute(
            """
            UPDATE messages
            SET content = $1
            WHERE id = $2
            """,
            update.content, message_id
        )
        edit_data = {
            "id": message_id,
            "content": update.content
        }
        if recipient["username"] in connections:
            await connections[recipient["username"]].send_json({"type": "edit", "data": edit_data})
        if current_user["username"] in connections:
            await connections[current_user["username"]].send_json({"type": "edit", "data": edit_data})
        logger.info(f"Message {message_id} edited by {current_user['username']}")
        return {"msg": "Message updated"}

# Delete message
@app.delete("/messages/{message_id}")
async def delete_message(message_id: int, current_user: dict = Depends(get_current_user)):
    async with db_pool.acquire() as conn:
        msg = await conn.fetchrow(
            """
            SELECT id, sender_id, recipient_id
            FROM messages
            WHERE id = $1
            """,
            message_id
        )
        if not msg:
            raise HTTPException(status_code=404, detail="Message not found")
        if msg["sender_id"] != current_user["id"] and msg["recipient_id"] != current_user["id"]:
            raise HTTPException(status_code=403, detail="Not authorized")
        recipient = await conn.fetchrow(
            "SELECT username FROM users WHERE id = $1",
            msg["recipient_id"] if msg["sender_id"] == current_user["id"] else msg["sender_id"]
        )
        await conn.execute("DELETE FROM messages WHERE id = $1", message_id)
        delete_data = {"id": message_id}
        if recipient and recipient["username"] in connections:
            await connections[recipient["username"]].send_json({"type": "delete", "data": delete_data})
        if current_user["username"] in connections:
            await connections[current_user["username"]].send_json({"type": "delete", "data": delete_data})
        logger.info(f"Message {message_id} deleted by {current_user['username']}")
        return {"msg": "Message deleted"}

# Mark message as read
@app.post("/messages/mark_read/{message_id}")
async def mark_message_read(message_id: int, current_user: dict = Depends(get_current_user)):
    async with db_pool.acquire() as conn:
        msg = await conn.fetchrow(
            """
            SELECT id, recipient_id
            FROM messages
            WHERE id = $1 AND recipient_id = $2
            """,
            message_id, current_user["id"]
        )
        if not msg:
            raise HTTPException(status_code=404, detail="Message not found or not authorized")
        await conn.execute(
            "UPDATE messages SET is_read = TRUE WHERE id = $1", message_id
        )
        sender = await conn.fetchrow(
            "SELECT username FROM users WHERE id = (SELECT sender_id FROM messages WHERE id = $1)",
            message_id
        )
        if sender and sender["username"] in connections:
            await connections[sender["username"]].send_json({"type": "read", "data": {"id": message_id}})
        logger.info(f"Message {message_id} marked as read by {current_user['username']}")
        return {"msg": "Message marked as read"}

# Get conversations
@app.get("/messages", response_model=List[Conversation])
async def get_conversations(current_user: dict = Depends(get_current_user)):
    async with db_pool.acquire() as conn:
        messages = await conn.fetch(
            """
            SELECT m.id, m.content, m.type, m.timestamp, m.is_read,
                   u1.username AS sender_username,
                   u2.username AS recipient_username
            FROM messages m
            JOIN users u1 ON m.sender_id = u1.id
            JOIN users u2 ON m.recipient_id = u2.id
            WHERE m.sender_id = $1 OR m.recipient_id = $1
            ORDER BY m.timestamp
            """,
            current_user["id"]
        )
        conversations = {}
        for msg in messages:
            other_user = msg["recipient_username"] if msg["sender_username"] == current_user["username"] else msg["sender_username"]
            if other_user not in conversations:
                conversations[other_user] = []
            conversations[other_user].append({
                "id": msg["id"],
                "sender_username": msg["sender_username"],
                "recipient_username": msg["recipient_username"],
                "content": msg["content"],
                "type": msg["type"],
                "timestamp": msg["timestamp"].isoformat() + "Z",
                "is_read": msg["is_read"]
            })
        result = [
            {"username": username, "messages": messages}
            for username, messages in conversations.items()
        ]
        logger.debug(f"Fetched {len(result)} conversations for {current_user['username']}")
        return result

# Delete conversation
@app.delete("/conversations/{username}")
async def delete_conversation(username: str, current_user: dict = Depends(get_current_user)):
    async with db_pool.acquire() as conn:
        other_user = await conn.fetchrow(
            "SELECT id FROM users WHERE username = $1", username
        )
        if not other_user:
            raise HTTPException(status_code=404, detail="User not found")
        if not await are_friends(conn, current_user["id"], other_user["id"]):
            raise HTTPException(status_code=403, detail="Not friends with user")
        await conn.execute(
            """
            DELETE FROM messages
            WHERE (sender_id = $1 AND recipient_id = $2)
            OR (sender_id = $2 AND recipient_id = $1)
            """,
            current_user["id"], other_user["id"]
        )
        logger.info(f"Conversation deleted with {username} by {current_user['username']}")
        return {"msg": "Conversation deleted"}

# WebSocket endpoint with heartbeat
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        async with db_pool.acquire() as conn:
            user = await conn.fetchrow("SELECT id, username FROM users WHERE id = $1", int(user_id))
            if not user:
                await websocket.close(code=4001, reason="Invalid user")
                return
        await websocket.accept()
        username = user["username"]
        connections[username] = websocket
        logger.info(f"WebSocket connected for {username}")

        # Broadcast user status
        status_data = {"username": username, "online": True}
        for conn in connections.values():
            if conn != websocket:
                await conn.send_json({"type": "status", "data": status_data})

        # Heartbeat to keep connection alive
        async def heartbeat():
            while True:
                try:
                    await websocket.send_json({"type": "ping"})
                    await asyncio.sleep(30)
                except Exception:
                    break

        heartbeat_task = asyncio.create_task(heartbeat())

        try:
            while True:
                data = await websocket.receive_json()
                if data.get("type") == "typing":
                    typing_data = {
                        "username": username,
                        "recipient": data["data"]["recipient"],
                        "isTyping": data["data"]["isTyping"]
                    }
                    recipient_username = data["data"]["recipient"]
                    if recipient_username in connections:
                        await connections[recipient_username].send_json({"type": "typing", "data": typing_data})
                    logger.debug(f"Typing event from {username} to {recipient_username}: isTyping={data['data']['isTyping']}")
                elif data.get("type") == "pong":
                    logger.debug(f"Received pong from {username}")
                else:
                    logger.warning(f"Unknown WebSocket message type from {username}: {data.get('type')}")
        except WebSocketDisconnect:
            logger.info(f"WebSocket disconnected for {username}")
        except Exception as e:
            logger.error(f"WebSocket error for {username}: {str(e)}")
        finally:
            heartbeat_task.cancel()
            if username in connections:
                del connections[username]
            status_data = {"username": username, "online": False}
            for conn in connections.values():
                await conn.send_json({"type": "status", "data": status_data})
            logger.info(f"WebSocket cleanup for {username}")
    except JWTError:
        await websocket.close(code=4001, reason="Invalid token")
        logger.warning("WebSocket connection rejected: Invalid token")

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
