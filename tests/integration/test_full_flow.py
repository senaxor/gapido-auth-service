"""End-to-end flow against a running docker compose stack.

The test plays the role of the SMS worker: it pulls the OTP job off the
RabbitMQ queue to learn the code, so the worker must not be competing for
messages. Run it like this:

    docker compose up -d --build
    docker compose stop worker
    make test-integration
    docker compose start worker

Environment overrides: AUTH_TARGET (default localhost:50051),
RABBITMQ_URL (default amqp://guest:guest@localhost:5672/%2F),
ADMIN_PHONE (default 09120000000, must be listed in ADMIN_PHONES in .env).
"""

from __future__ import annotations

import json
import os
import secrets
import time

import grpc
import pika
import pytest

from gapido_auth.messaging import topology
from gapido_auth.proto import auth_pb2, auth_pb2_grpc, demo_pb2, demo_pb2_grpc

pytestmark = pytest.mark.integration

AUTH_TARGET = os.environ.get("AUTH_TARGET", "localhost:50051")
RABBITMQ_URL = os.environ.get("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/%2F")
ADMIN_PHONE = os.environ.get("ADMIN_PHONE", "09120000000")


@pytest.fixture(scope="module")
def channel():
    channel = grpc.insecure_channel(AUTH_TARGET)
    try:
        grpc.channel_ready_future(channel).result(timeout=5)
    except grpc.FutureTimeoutError:
        pytest.skip(f"no gRPC server at {AUTH_TARGET}; is docker compose up?")
    yield channel
    channel.close()


@pytest.fixture(scope="module")
def auth_stub(channel):
    return auth_pb2_grpc.AuthServiceStub(channel)


@pytest.fixture(scope="module")
def demo_stub(channel):
    return demo_pb2_grpc.DemoServiceStub(channel)


def pluck_otp_from_queue(phone: str, timeout: float = 10.0) -> str:
    """Consume sms.otp until we find the job for ``phone``."""
    connection = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URL))
    rabbit = connection.channel()
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            method, _properties, body = rabbit.basic_get(topology.QUEUE_MAIN)
            if method is None:
                time.sleep(0.2)
                continue
            job = json.loads(body)
            rabbit.basic_ack(method.delivery_tag)
            if job["phone"] == phone:
                return job["code"]
        pytest.fail(
            f"OTP job for {phone} not seen on {topology.QUEUE_MAIN} within {timeout}s "
            "(is the worker stopped? `docker compose stop worker`)"
        )
    finally:
        connection.close()


def login(auth_stub, phone: str) -> auth_pb2.TokenPair:
    auth_stub.RequestOtp(auth_pb2.RequestOtpRequest(phone=phone))
    code = pluck_otp_from_queue(phone)
    return auth_stub.VerifyOtp(auth_pb2.VerifyOtpRequest(phone=phone, code=code))


def random_phone() -> str:
    return "091" + "".join(str(secrets.randbelow(10)) for _ in range(8))


def auth_metadata(pair: auth_pb2.TokenPair):
    return (("authorization", f"Bearer {pair.access_token}"),)


def test_full_user_journey(auth_stub, demo_stub):
    phone = random_phone()

    # public endpoint, no token
    assert demo_stub.GetPublicNotice(demo_pb2.Empty()).message

    # protected endpoint rejects anonymous callers
    with pytest.raises(grpc.RpcError) as exc_info:
        demo_stub.GetMyProfile(demo_pb2.Empty())
    assert exc_info.value.code() == grpc.StatusCode.UNAUTHENTICATED

    # OTP login
    pair = login(auth_stub, phone)
    assert pair.token_type == "Bearer"

    # authenticated endpoint now works
    profile = demo_stub.GetMyProfile(demo_pb2.Empty(), metadata=auth_metadata(pair))
    assert profile.phone == phone
    assert profile.role == "user"

    # plain users cannot reach the admin endpoint
    with pytest.raises(grpc.RpcError) as exc_info:
        demo_stub.ListUsers(demo_pb2.ListUsersRequest(), metadata=auth_metadata(pair))
    assert exc_info.value.code() == grpc.StatusCode.PERMISSION_DENIED

    # refresh rotates the pair; the old refresh token dies
    new_pair = auth_stub.RefreshToken(
        auth_pb2.RefreshTokenRequest(refresh_token=pair.refresh_token)
    )
    assert new_pair.refresh_token != pair.refresh_token
    with pytest.raises(grpc.RpcError) as exc_info:
        auth_stub.RefreshToken(
            auth_pb2.RefreshTokenRequest(refresh_token=pair.refresh_token)
        )
    assert exc_info.value.code() == grpc.StatusCode.UNAUTHENTICATED

    # replaying the rotated token above revoked the family: logout is a no-op
    # on dead tokens but the new access token still authenticates until expiry
    demo_stub.GetMyProfile(demo_pb2.Empty(), metadata=auth_metadata(new_pair))

    # logout
    auth_stub.Logout(auth_pb2.LogoutRequest(refresh_token=new_pair.refresh_token))


def test_wrong_code_rejected(auth_stub):
    phone = random_phone()
    auth_stub.RequestOtp(auth_pb2.RequestOtpRequest(phone=phone))
    pluck_otp_from_queue(phone)  # drain the real code
    with pytest.raises(grpc.RpcError) as exc_info:
        auth_stub.VerifyOtp(auth_pb2.VerifyOtpRequest(phone=phone, code="000000"))
    assert exc_info.value.code() == grpc.StatusCode.UNAUTHENTICATED


def test_resend_cooldown_enforced(auth_stub):
    phone = random_phone()
    auth_stub.RequestOtp(auth_pb2.RequestOtpRequest(phone=phone))
    with pytest.raises(grpc.RpcError) as exc_info:
        auth_stub.RequestOtp(auth_pb2.RequestOtpRequest(phone=phone))
    assert exc_info.value.code() == grpc.StatusCode.RESOURCE_EXHAUSTED


def test_admin_journey(auth_stub, demo_stub):
    try:
        pair = login(auth_stub, ADMIN_PHONE)
    except grpc.RpcError as exc:
        if exc.code() == grpc.StatusCode.RESOURCE_EXHAUSTED:
            pytest.skip("admin phone is in OTP cooldown from a previous run")
        raise
    reply = demo_stub.ListUsers(demo_pb2.ListUsersRequest(), metadata=auth_metadata(pair))
    assert reply.total >= 1
    assert any(u.role == "admin" for u in reply.users)
