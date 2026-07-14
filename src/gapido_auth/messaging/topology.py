"""RabbitMQ topology shared by the publisher (gRPC server) and the worker.

Retry design (no plugins, plain AMQP):

    sms (direct) --otp--> sms.otp  ==worker nack==>  sms.dlx --otp.retry-->
    sms.otp.retry [TTL] --expires back to--> sms --otp--> sms.otp

- Transient delivery failures are nack'ed (requeue=False); the message dead-
  letters into the retry queue, sits out RETRY_DELAY_MS, then re-enters the
  main queue. RabbitMQ's x-death header counts the round trips.
- After MAX_DELIVERY_ATTEMPTS, or on permanent provider errors, the message
  is parked in sms.otp.dead for inspection and the delivery is acked.
"""

from __future__ import annotations

import pika

EXCHANGE = "sms"
DLX_EXCHANGE = "sms.dlx"

QUEUE_MAIN = "sms.otp"
QUEUE_RETRY = "sms.otp.retry"
QUEUE_DEAD = "sms.otp.dead"

RK_MAIN = "otp"
RK_RETRY = "otp.retry"
RK_DEAD = "otp.dead"

RETRY_DELAY_MS = 15_000
MAX_DELIVERY_ATTEMPTS = 4  # initial delivery + 3 retries


def declare(channel: pika.channel.Channel) -> None:
    """Declare the full topology; idempotent, run by every process on boot."""
    channel.exchange_declare(EXCHANGE, exchange_type="direct", durable=True)
    channel.exchange_declare(DLX_EXCHANGE, exchange_type="direct", durable=True)

    channel.queue_declare(
        QUEUE_MAIN,
        durable=True,
        arguments={
            "x-dead-letter-exchange": DLX_EXCHANGE,
            "x-dead-letter-routing-key": RK_RETRY,
        },
    )
    channel.queue_bind(QUEUE_MAIN, EXCHANGE, RK_MAIN)

    channel.queue_declare(
        QUEUE_RETRY,
        durable=True,
        arguments={
            "x-message-ttl": RETRY_DELAY_MS,
            "x-dead-letter-exchange": EXCHANGE,
            "x-dead-letter-routing-key": RK_MAIN,
        },
    )
    channel.queue_bind(QUEUE_RETRY, DLX_EXCHANGE, RK_RETRY)

    channel.queue_declare(QUEUE_DEAD, durable=True)
    channel.queue_bind(QUEUE_DEAD, DLX_EXCHANGE, RK_DEAD)


def delivery_attempt(properties: pika.BasicProperties) -> int:
    """1 for the first delivery, incremented per retry round trip (x-death)."""
    headers = properties.headers or {}
    for death in headers.get("x-death", []):
        if death.get("queue") == QUEUE_MAIN:
            return int(death.get("count", 0)) + 1
    return 1
