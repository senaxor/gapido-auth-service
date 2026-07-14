"""gRPC server entrypoint: wires config, Mongo, RabbitMQ and servicers."""

from __future__ import annotations

import logging
import signal
import threading
from concurrent import futures

import grpc
from grpc_health.v1 import health, health_pb2, health_pb2_grpc
from grpc_reflection.v1alpha import reflection

from gapido_auth.config import Config
from gapido_auth.core.otp import OtpService
from gapido_auth.core.tokens import TokenService
from gapido_auth.db import create_database, ensure_indexes
from gapido_auth.db.repositories import (
    OtpRepository,
    RefreshTokenRepository,
    UserRepository,
)
from gapido_auth.interceptors import AuthInterceptor
from gapido_auth.messaging.publisher import SmsJobPublisher
from gapido_auth.proto import auth_pb2, auth_pb2_grpc, demo_pb2, demo_pb2_grpc
from gapido_auth.services import AuthServicer, DemoServicer

logger = logging.getLogger(__name__)


def build_server(config: Config) -> tuple[grpc.Server, SmsJobPublisher]:
    db = create_database(config)
    ensure_indexes(db)

    users = UserRepository(db)
    otps = OtpRepository(db)
    refresh_tokens = RefreshTokenRepository(db)

    otp_service = OtpService(config, otps)
    token_service = TokenService(config, refresh_tokens, users)
    publisher = SmsJobPublisher(config.rabbitmq_url)

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=16),
        interceptors=[AuthInterceptor(token_service)],
    )
    auth_pb2_grpc.add_AuthServiceServicer_to_server(
        AuthServicer(config, otp_service, token_service, users, publisher), server
    )
    demo_pb2_grpc.add_DemoServiceServicer_to_server(DemoServicer(users), server)

    health_servicer = health.HealthServicer()
    health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)

    service_names = (
        auth_pb2.DESCRIPTOR.services_by_name["AuthService"].full_name,
        demo_pb2.DESCRIPTOR.services_by_name["DemoService"].full_name,
        health.SERVICE_NAME,
        reflection.SERVICE_NAME,
    )
    reflection.enable_server_reflection(service_names, server)

    server.add_insecure_port(f"[::]:{config.grpc_port}")
    return server, publisher


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    config = Config.from_env()
    server, publisher = build_server(config)
    server.start()
    logger.info("gRPC server listening on :%d", config.grpc_port)

    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    stop.wait()

    logger.info("shutting down")
    server.stop(grace=10).wait()
    publisher.close()


if __name__ == "__main__":
    main()
