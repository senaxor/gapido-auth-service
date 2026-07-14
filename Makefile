.PHONY: install env proto test test-integration up down logs

install:
	pip install -e ".[dev]"

# Create .env from the template with freshly generated secrets.
env:
	cp -n .env.example .env
	sed -i "s|^JWT_SECRET=.*|JWT_SECRET=$$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')|" .env
	sed -i "s|^OTP_PEPPER=.*|OTP_PEPPER=$$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')|" .env

proto:
	python -m grpc_tools.protoc -Iprotos \
		--python_out=src/gapido_auth/proto \
		--grpc_python_out=src/gapido_auth/proto \
		protos/auth.proto protos/demo.proto
	sed -i 's/^import \(auth\|demo\)_pb2/from . import \1_pb2/' \
		src/gapido_auth/proto/*_grpc.py src/gapido_auth/proto/demo_pb2.py

test:
	pytest

test-integration:
	pytest -m integration

up:
	docker compose up --build -d

down:
	docker compose down -v

logs:
	docker compose logs -f server worker
