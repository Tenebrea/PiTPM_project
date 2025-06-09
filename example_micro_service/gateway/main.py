from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import aio_pika
import uuid
import asyncio
import json

app = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    app.state.connection = await aio_pika.connect_robust("amqp://user1:password1@77.91.86.135:5672/vhost_user1")
    app.state.channel = await app.state.connection.channel()

async def rpc_call(routing_key: str, message: dict):
    correlation_id = str(uuid.uuid4())
    future = asyncio.get_event_loop().create_future()

    callback_queue = await app.state.channel.declare_queue(exclusive=True)
    
    async def on_response(msg: aio_pika.IncomingMessage):
        if msg.correlation_id == correlation_id:
            future.set_result(msg.body)

    await callback_queue.consume(on_response)

    await app.state.channel.default_exchange.publish(
        aio_pika.Message(
            body=json.dumps(message).encode(),
            correlation_id=correlation_id,
            reply_to=callback_queue.name,
        ),
        routing_key=routing_key,
    )

    result = await future
    return json.loads(result.decode())

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/auth/me")
async def auth_me():
    return await rpc_call("auth_queue", {"action": "get_me", "token": "token123"})

@app.get("/api/courses")
async def get_courses():
    return await rpc_call("course_queue", {"action": "list_courses"})
