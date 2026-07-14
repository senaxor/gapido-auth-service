"""Access-control tests against a real in-process gRPC server.

Exercises the three challenge access levels through the actual interceptor:
public, authenticated-only, admin-only.
"""

from concurrent import futures

import grpc
import pytest

from gapido_auth.core.tokens import TokenService
from gapido_auth.interceptors import AuthInterceptor
from gapido_auth.proto import demo_pb2, demo_pb2_grpc
from gapido_auth.services import DemoServicer

from tests.conftest import ADMIN_PHONE


@pytest.fixture
def env(config, refresh_repo, user_repo):
    token_service = TokenService(config, refresh_repo, user_repo)
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=2),
        interceptors=[AuthInterceptor(token_service)],
    )
    demo_pb2_grpc.add_DemoServiceServicer_to_server(DemoServicer(user_repo), server)
    port = server.add_insecure_port("localhost:0")
    server.start()
    channel = grpc.insecure_channel(f"localhost:{port}")
    yield token_service, user_repo, demo_pb2_grpc.DemoServiceStub(channel)
    channel.close()
    server.stop(grace=None)


def bearer(token_service, user):
    pair = token_service.issue_pair(user)
    return (("authorization", f"Bearer {pair.access_token}"),)


def status_of(call):
    with pytest.raises(grpc.RpcError) as exc_info:
        call()
    return exc_info.value.code()


def test_public_method_needs_no_token(env):
    _, _, stub = env
    reply = stub.GetPublicNotice(demo_pb2.Empty())
    assert "public" in reply.message


def test_authenticated_method_rejects_anonymous(env):
    _, _, stub = env
    code = status_of(lambda: stub.GetMyProfile(demo_pb2.Empty()))
    assert code == grpc.StatusCode.UNAUTHENTICATED


def test_authenticated_method_rejects_bad_token(env):
    _, _, stub = env
    code = status_of(
        lambda: stub.GetMyProfile(
            demo_pb2.Empty(), metadata=(("authorization", "Bearer garbage"),)
        )
    )
    assert code == grpc.StatusCode.UNAUTHENTICATED


def test_authenticated_method_accepts_user(env):
    tokens, users, stub = env
    user = users.get_or_create("09123456789", "user")
    profile = stub.GetMyProfile(demo_pb2.Empty(), metadata=bearer(tokens, user))
    assert profile.phone == "09123456789"
    assert profile.role == "user"


def test_admin_method_rejects_plain_user(env):
    tokens, users, stub = env
    user = users.get_or_create("09123456789", "user")
    code = status_of(
        lambda: stub.ListUsers(demo_pb2.ListUsersRequest(), metadata=bearer(tokens, user))
    )
    assert code == grpc.StatusCode.PERMISSION_DENIED


def test_admin_method_rejects_anonymous(env):
    _, _, stub = env
    code = status_of(lambda: stub.ListUsers(demo_pb2.ListUsersRequest()))
    assert code == grpc.StatusCode.UNAUTHENTICATED


def test_admin_method_accepts_admin(env):
    tokens, users, stub = env
    users.get_or_create("09123456789", "user")
    admin = users.get_or_create(ADMIN_PHONE, "admin")
    reply = stub.ListUsers(demo_pb2.ListUsersRequest(), metadata=bearer(tokens, admin))
    assert reply.total == 2
    assert {u.role for u in reply.users} == {"user", "admin"}
