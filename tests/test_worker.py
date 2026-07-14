import json
from types import SimpleNamespace

import pika
import pytest

from gapido_auth.messaging import topology
from gapido_auth.sms.provider import PermanentSmsError, TransientSmsError
from gapido_auth.worker import SmsWorker


class FakeChannel:
    def __init__(self):
        self.acked, self.nacked, self.published = [], [], []

    def basic_ack(self, delivery_tag):
        self.acked.append(delivery_tag)

    def basic_nack(self, delivery_tag, requeue):
        self.nacked.append((delivery_tag, requeue))

    def basic_publish(self, exchange, routing_key, body, properties):
        self.published.append(
            {"exchange": exchange, "routing_key": routing_key,
             "body": body, "properties": properties}
        )


class RecordingProvider:
    def __init__(self, error=None):
        self.error = error
        self.sent = []

    def send_otp(self, phone, code):
        if self.error:
            raise self.error
        self.sent.append((phone, code))


def make_job(phone="09123456789", code="123456"):
    return json.dumps({"type": "otp", "phone": phone, "code": code}).encode()


def deliver(worker, channel, body, attempt=1):
    method = SimpleNamespace(delivery_tag=7)
    headers = {}
    if attempt > 1:
        headers["x-death"] = [{"queue": topology.QUEUE_MAIN, "count": attempt - 1}]
    worker.handle(channel, method, pika.BasicProperties(headers=headers), body)


@pytest.fixture
def channel():
    return FakeChannel()


def test_successful_delivery_acks(config, channel):
    provider = RecordingProvider()
    deliver(SmsWorker(config, provider), channel, make_job())
    assert provider.sent == [("09123456789", "123456")]
    assert channel.acked == [7]
    assert not channel.nacked and not channel.published


def test_transient_failure_nacks_for_retry(config, channel):
    worker = SmsWorker(config, RecordingProvider(TransientSmsError("down")))
    deliver(worker, channel, make_job())
    assert channel.nacked == [(7, False)]
    assert not channel.acked and not channel.published


def test_permanent_failure_parks_and_acks(config, channel):
    worker = SmsWorker(config, RecordingProvider(PermanentSmsError("bad template")))
    deliver(worker, channel, make_job())
    assert channel.acked == [7]
    parked = channel.published[0]
    assert parked["exchange"] == topology.DLX_EXCHANGE
    assert parked["routing_key"] == topology.RK_DEAD
    assert "bad template" in parked["properties"].headers["x-failure-reason"]


def test_exhausted_retries_park(config, channel):
    worker = SmsWorker(config, RecordingProvider(TransientSmsError("still down")))
    deliver(worker, channel, make_job(), attempt=topology.MAX_DELIVERY_ATTEMPTS)
    assert channel.acked == [7]
    assert channel.published[0]["routing_key"] == topology.RK_DEAD
    assert not channel.nacked


def test_malformed_job_parks(config, channel):
    worker = SmsWorker(config, RecordingProvider())
    deliver(worker, channel, b"{not json")
    assert channel.acked == [7]
    assert channel.published[0]["routing_key"] == topology.RK_DEAD


def test_delivery_attempt_counting():
    assert topology.delivery_attempt(pika.BasicProperties()) == 1
    props = pika.BasicProperties(
        headers={"x-death": [{"queue": topology.QUEUE_MAIN, "count": 2}]}
    )
    assert topology.delivery_attempt(props) == 3
