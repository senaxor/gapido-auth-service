"""SMS delivery worker.

Consumes OTP jobs from RabbitMQ and delivers them through the configured
SMS provider. Failure handling:

- TransientSmsError  -> nack (no requeue); the message dead-letters into the
  delayed retry queue and comes back after topology.RETRY_DELAY_MS.
- PermanentSmsError, malformed jobs, or exhausted retries -> the message is
  parked in the dead-letter queue with a failure reason header, then acked.
"""

from __future__ import annotations

import json
import logging
import signal
import time

import pika

from gapido_auth.config import Config
from gapido_auth.messaging import topology
from gapido_auth.sms import PermanentSmsError, SmsProvider, TransientSmsError, build_provider

logger = logging.getLogger(__name__)


class SmsWorker:
    def __init__(self, config: Config, provider: SmsProvider) -> None:
        self._config = config
        self._provider = provider
        self._connection: pika.BlockingConnection | None = None
        self._channel: pika.channel.Channel | None = None
        self._stopping = False

    # -- message handling ----------------------------------------------------

    def handle(self, channel, method, properties, body: bytes) -> None:
        attempt = topology.delivery_attempt(properties)
        try:
            job = json.loads(body)
            phone, code = job["phone"], job["code"]
        except (ValueError, KeyError, TypeError) as exc:
            logger.error("malformed sms job, parking it: %s", exc)
            self._park(channel, body, reason=f"malformed job: {exc}")
            channel.basic_ack(method.delivery_tag)
            return

        try:
            self._provider.send_otp(phone, code)
        except PermanentSmsError as exc:
            logger.error("permanent delivery failure for %s: %s", phone, exc)
            self._park(channel, body, reason=str(exc))
            channel.basic_ack(method.delivery_tag)
        except TransientSmsError as exc:
            if attempt >= topology.MAX_DELIVERY_ATTEMPTS:
                logger.error(
                    "giving up on %s after %d attempts: %s", phone, attempt, exc
                )
                self._park(channel, body, reason=f"retries exhausted: {exc}")
                channel.basic_ack(method.delivery_tag)
            else:
                logger.warning(
                    "transient failure for %s (attempt %d/%d), retrying: %s",
                    phone, attempt, topology.MAX_DELIVERY_ATTEMPTS, exc,
                )
                channel.basic_nack(method.delivery_tag, requeue=False)
        else:
            logger.info("otp sms delivered to %s (attempt %d)", phone, attempt)
            channel.basic_ack(method.delivery_tag)

    @staticmethod
    def _park(channel, body: bytes, reason: str) -> None:
        channel.basic_publish(
            exchange=topology.DLX_EXCHANGE,
            routing_key=topology.RK_DEAD,
            body=body,
            properties=pika.BasicProperties(
                content_type="application/json",
                delivery_mode=pika.DeliveryMode.Persistent,
                headers={"x-failure-reason": reason[:500]},
            ),
        )

    # -- lifecycle -------------------------------------------------------------

    def run_forever(self) -> None:
        signal.signal(signal.SIGTERM, self._request_stop)
        signal.signal(signal.SIGINT, self._request_stop)
        while not self._stopping:
            try:
                self._consume()
            except pika.exceptions.AMQPConnectionError as exc:
                if self._stopping:
                    break
                logger.warning("broker connection lost (%s), reconnecting in 5s", exc)
                time.sleep(5)
        logger.info("worker stopped")

    def _consume(self) -> None:
        self._connection = pika.BlockingConnection(
            pika.URLParameters(self._config.rabbitmq_url)
        )
        self._channel = self._connection.channel()
        topology.declare(self._channel)
        self._channel.basic_qos(prefetch_count=8)
        self._channel.basic_consume(topology.QUEUE_MAIN, self.handle)
        logger.info("worker consuming %s", topology.QUEUE_MAIN)
        try:
            self._channel.start_consuming()
        finally:
            if self._connection.is_open:
                self._connection.close()

    def _request_stop(self, signum, _frame) -> None:
        logger.info("signal %d received, shutting down", signum)
        self._stopping = True
        if self._connection is not None and self._connection.is_open:
            # The only thread-safe way to break start_consuming() from outside
            # the connection's I/O loop.
            self._connection.add_callback_threadsafe(self._channel.stop_consuming)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    config = Config.from_env()
    provider = build_provider(config)
    logger.info("starting sms worker with provider=%s", config.sms_provider)
    SmsWorker(config, provider).run_forever()


if __name__ == "__main__":
    main()
