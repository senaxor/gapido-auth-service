"""Publishes OTP delivery jobs to RabbitMQ.

pika's BlockingConnection is not thread-safe and gRPC handlers run on a
thread pool, so all channel access is serialized behind a lock. Publishes
use publisher confirms and persistent delivery; a broken connection is
re-established once per publish attempt.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone

import pika

from gapido_auth.messaging import topology

logger = logging.getLogger(__name__)


class PublishError(Exception):
    """The job could not be handed to the broker."""


class SmsJobPublisher:
    def __init__(self, amqp_url: str) -> None:
        self._params = pika.URLParameters(amqp_url)
        self._lock = threading.Lock()
        self._connection: pika.BlockingConnection | None = None
        self._channel: pika.channel.Channel | None = None

    def _ensure_channel(self) -> pika.channel.Channel:
        if self._channel is None or not self._channel.is_open:
            self._connection = pika.BlockingConnection(self._params)
            self._channel = self._connection.channel()
            topology.declare(self._channel)
            self._channel.confirm_delivery()
        return self._channel

    def publish_otp(self, phone: str, code: str) -> None:
        body = json.dumps(
            {
                "type": "otp",
                "phone": phone,
                "code": code,
                "requested_at": datetime.now(timezone.utc).isoformat(),
            }
        ).encode()

        with self._lock:
            for attempt in (1, 2):
                try:
                    channel = self._ensure_channel()
                    channel.basic_publish(
                        exchange=topology.EXCHANGE,
                        routing_key=topology.RK_MAIN,
                        body=body,
                        properties=pika.BasicProperties(
                            content_type="application/json",
                            delivery_mode=pika.DeliveryMode.Persistent,
                        ),
                        mandatory=True,
                    )
                    return
                except pika.exceptions.AMQPError as exc:
                    logger.warning("publish attempt %d failed: %s", attempt, exc)
                    self._reset()
        raise PublishError("could not enqueue SMS job after reconnect")

    def _reset(self) -> None:
        try:
            if self._connection is not None and self._connection.is_open:
                self._connection.close()
        except pika.exceptions.AMQPError:  # already broken; nothing to salvage
            pass
        self._connection = None
        self._channel = None

    def close(self) -> None:
        with self._lock:
            self._reset()
