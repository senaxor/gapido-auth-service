"""DemoService gRPC servicer: one method per access level.

Authorization already happened in AuthInterceptor by the time these run;
the verified caller identity is available via ``current_claims``.
"""

from __future__ import annotations

import grpc

from gapido_auth.db.repositories import User, UserRepository
from gapido_auth.interceptors import current_claims
from gapido_auth.proto import demo_pb2, demo_pb2_grpc

_MAX_PAGE_SIZE = 100


def _profile(user: User) -> demo_pb2.Profile:
    return demo_pb2.Profile(
        user_id=user.id,
        phone=user.phone,
        role=user.role,
        created_at=user.created_at.isoformat(),
    )


class DemoServicer(demo_pb2_grpc.DemoServiceServicer):
    def __init__(self, users: UserRepository) -> None:
        self._users = users

    def GetPublicNotice(self, request, context):
        return demo_pb2.PublicNotice(
            message="Welcome to Gapido auth service. This endpoint is public."
        )

    def GetMyProfile(self, request, context):
        claims = current_claims.get()
        user = self._users.get_by_id(claims.user_id)
        if user is None:
            context.abort(grpc.StatusCode.NOT_FOUND, "user no longer exists")
        return _profile(user)

    def ListUsers(self, request, context):
        page = max(request.page, 1)
        page_size = min(request.page_size or 20, _MAX_PAGE_SIZE)
        users, total = self._users.list_page(page, page_size)
        return demo_pb2.ListUsersResponse(users=[_profile(u) for u in users], total=total)
