#!/usr/bin/env python3
"""
Многопоточный TLS-сервер для тестов прокси.

Принимает любое количество одновременных TLS-соединений,
делает handshake, печатает SNI клиента и закрывает.
Идеально для probe: пока upstream ещё не открыт, probe
подключается и получает сертификат без блокировки.
"""

import argparse
import socket
import socketserver
import ssl
import sys
import threading
from datetime import datetime


def log(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"[{ts}] [{threading.current_thread().name}] {msg}", flush=True)


class TlsHandler(socketserver.BaseRequestHandler):
    """Обработчик одного TCP-соединения."""

    def handle(self) -> None:
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        log(f"TCP accepted from {peer}")

        try:
            # Оборачиваем сокет в TLS. handshake выполняется здесь.
            tls_sock = self.server.ssl_context.wrap_socket(
                self.request,
                server_side=True,
            )

            sni = tls_sock.server_hostname or "(no SNI)"
            version = tls_sock.version()
            cipher = tls_sock.cipher()

            log(f"TLS handshake OK: peer={peer} SNI={sni} "
                f"version={version} cipher={cipher[0] if cipher else '?'}")

            # Показываем сертификат, который клиент получит.
            cert = tls_sock.getpeercert()
            if cert:
                log(f"  client cert subject: {cert.get('subject')}")

            # Читаем, что пришло — ClientHello уже позади, дальше идут
            # application data. Для probe обычно ничего.
            tls_sock.settimeout(2.0)
            try:
                data = tls_sock.recv(4096)
                if data:
                    log(f"  app data: {len(data)} bytes")
                else:
                    log(f"  connection closed by peer")
            except socket.timeout:
                log(f"  no app data (timeout), closing")

            try:
                tls_sock.unwrap()
            except (ssl.SSLError, OSError):
                pass
            tls_sock.close()

        except ssl.SSLError as e:
            log(f"TLS error from {peer}: {e}")
        except (ConnectionResetError, BrokenPipeError):
            log(f"peer {peer} disconnected abruptly")
        except Exception as e:
            log(f"unexpected error from {peer}: {type(e).__name__}: {e}")


class ThreadedTlsServer(socketserver.ThreadingTCPServer):
    """ThreadingTCPServer с SSLContext."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, handler, ssl_context):
        self.ssl_context = ssl_context
        super().__init__(addr, handler)


def main() -> int:
    parser = argparse.ArgumentParser(description="Threaded TLS test server")
    parser.add_argument("--host", default="10.0.1.1", help="Listen address")
    parser.add_argument("--port", type=int, default=8443, help="Listen port")
    parser.add_argument("--cert", required=True, help="Path to server certificate (PEM)")
    parser.add_argument("--key", required=True, help="Path to server private key (PEM)")
    parser.add_argument("--ca", default=None, help="Optional CA for client cert verification")
    parser.add_argument("--min-tls", default="TLSv1.2",
                        choices=["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"],
                        help="Minimum TLS version")
    args = parser.parse_args()

    # ── SSL context ──
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)

    min_ver = {
        "TLSv1":   ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }[args.min_tls]
    ctx.minimum_version = min_ver
    ctx.maximum_version = min_ver

    # Клиентские сертификаты — не проверяем по умолчанию.
    ctx.verify_mode = ssl.CERT_NONE
    if args.ca:
        ctx.load_verify_locations(args.ca)
        ctx.verify_mode = ssl.CERT_OPTIONAL

    # Отключаем сессионные тикеты для чистого probe (по желанию).
    # ctx.options |= ssl.OP_NO_TICKET

    # ── Сервер ──
    server = ThreadedTlsServer((args.host, args.port), TlsHandler, ctx)
    log(f"TLS server listening on {args.host}:{args.port}")
    log(f"  cert={args.cert} key={args.key} min_tls={args.min_tls}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("shutting down")
    finally:
        server.server_close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
