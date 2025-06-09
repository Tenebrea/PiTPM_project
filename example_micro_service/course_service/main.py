import asyncio
import aio_pika
import json
from aio_pika.abc import AbstractIncomingMessage

async def main():
    connection = await aio_pika.connect_robust("amqp://user1:password1@77.91.86.135:5672/vhost_user1")
    channel = await connection.channel()
    queue = await channel.declare_queue("course_queue")

    async def handle_message(message: AbstractIncomingMessage):
        async with message.process():
            courses = [
                {"id": 1, "title": "FastAPI"},
                {"id": 2, "title": "RabbitMQ"}
            ]

            if message.reply_to:
                await channel.default_exchange.publish(
                    aio_pika.Message(
                        body=json.dumps(courses).encode(),
                        correlation_id=message.correlation_id
                    ),
                    routing_key=message.reply_to
                )

    await queue.consume(handle_message)
    print("Course service started")
    await asyncio.Future()

asyncio.run(main())
