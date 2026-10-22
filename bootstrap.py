import asyncio
import logging
import os
import signal
import socket
import ssl
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

import aiohttp
from aiohttp import web
import dnslib
from dnslib import DNSRecord, QTYPE, RR, A, RCODE
from dotenv import load_dotenv
import httpx

SCRIPT_DIR = Path(__file__).resolve().parent

INTERCEPTED_DOMAINS = {
    "quasar.yandex.net",
    "quasar.yandex.ru",
    "scbh.yandex.net",
}

SYNC_INFO_PAYLOAD = (
    '{"status":"ok","config":{"account_config":{"spotter":"alisa"},'
    '"device_config":{"name":"quasar"},"system_config":{"adbd":'
    '{"remoteActivation":true,"network":true}}},"subscription":{"mode":"transaction"}}'
)

CHECK_UPDATES_PAYLOAD = '{"hasUpdate":false}'


def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return str(s.getsockname()[0])
    except OSError:
        return "127.0.0.1"


@dataclass(frozen=True)
class Config:
    bind_ip: str
    target_ip: str
    dns_port: int
    http_port: int
    https_port: int
    upstream_dns_host: str
    upstream_dns_port: int
    cert_file: Path
    key_file: Path
    access_log_path: Path
    error_log_path: Path
    log_level: str
    proxy_timeout: float
    retry_count: int
    max_body_size: int

    @classmethod
    def from_env(cls, env_file: Optional[Path] = None) -> "Config":
        if env_file is None:
            env_file_raw = os.environ.get("ENV_FILE", ".env").strip()
            env_path = Path(env_file_raw) if Path(env_file_raw).is_absolute() else SCRIPT_DIR / env_file_raw
        else:
            env_path = env_file

        if env_path.is_file():
            load_dotenv(dotenv_path=env_path, override=False)

        bind_ip = os.environ.get("BIND_IP", "0.0.0.0").strip()
        target_ip = os.environ.get("TARGET_IP", "").strip() or get_local_ip()
        dns_port = int(os.environ.get("DNS_PORT", "53"))
        http_port = int(os.environ.get("HTTP_PORT", "80"))
        https_port = int(os.environ.get("HTTPS_PORT", "443"))

        upstream_raw = os.environ.get("UPSTREAM_DNS", "8.8.8.8:53").strip()
        if ":" in upstream_raw:
            up_host, up_port_str = upstream_raw.rsplit(":", 1)
            up_port = int(up_port_str)
        else:
            up_host = upstream_raw
            up_port = 53

        cert_name = os.environ.get("CERT_FILE", "fullchain.pem").strip()
        key_name = os.environ.get("KEY_FILE", "quasar-all.key").strip()
        cert_file = Path(cert_name) if Path(cert_name).is_absolute() else SCRIPT_DIR / cert_name
        key_file = Path(key_name) if Path(key_name).is_absolute() else SCRIPT_DIR / key_name

        access_log_raw = os.environ.get("ACCESS_LOG", str(SCRIPT_DIR / "quasar.yandex.net.access.log")).strip()
        error_log_raw = os.environ.get("ERROR_LOG", str(SCRIPT_DIR / "quasar.yandex.net.error.log")).strip()

        log_level = os.environ.get("LOG_LEVEL", "INFO").upper().strip()
        proxy_timeout = float(os.environ.get("PROXY_TIMEOUT", "3600"))
        retry_count = max(1, int(os.environ.get("RETRY_COUNT", "3")))
        max_body_size = max(1024, int(os.environ.get("MAX_BODY_SIZE", str(10 * 1024 * 1024))))

        return cls(
            bind_ip=bind_ip,
            target_ip=target_ip,
            dns_port=dns_port,
            http_port=http_port,
            https_port=https_port,
            upstream_dns_host=up_host,
            upstream_dns_port=up_port,
            cert_file=cert_file,
            key_file=key_file,
            access_log_path=Path(access_log_raw),
            error_log_path=Path(error_log_raw),
            log_level=log_level,
            proxy_timeout=proxy_timeout,
            retry_count=retry_count,
            max_body_size=max_body_size,
        )


def setup_loggers(config: Config) -> Tuple[logging.Logger, logging.Logger]:
    level = getattr(logging, config.log_level, logging.INFO)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", "%Y-%m-%dT%H:%M:%SZ")

    error_logger = logging.getLogger("quasar.error")
    error_logger.setLevel(level)
    error_logger.handlers.clear()
    error_logger.propagate = False

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(formatter)
    error_logger.addHandler(stream_handler)

    try:
        config.error_log_path.parent.mkdir(parents=True, exist_ok=True)
        err_file_handler = logging.FileHandler(config.error_log_path, encoding="utf-8")
        err_file_handler.setFormatter(formatter)
        error_logger.addHandler(err_file_handler)
    except OSError as exc:
        error_logger.warning("Cannot open error log file %s: %s", config.error_log_path, exc)

    access_logger = logging.getLogger("quasar.access")
    access_logger.setLevel(level)
    access_logger.handlers.clear()
    access_logger.propagate = False

    access_stream = logging.StreamHandler(sys.stdout)
    access_stream.setFormatter(formatter)
    access_logger.addHandler(access_stream)

    try:
        config.access_log_path.parent.mkdir(parents=True, exist_ok=True)
        acc_file_handler = logging.FileHandler(config.access_log_path, encoding="utf-8")
        acc_file_handler.setFormatter(formatter)
        access_logger.addHandler(acc_file_handler)
    except OSError as exc:
        error_logger.warning("Cannot open access log file %s: %s", config.access_log_path, exc)

    return access_logger, error_logger


class _UdpQueryClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, payload: bytes, future: asyncio.Future[bytes]) -> None:
        self.payload = payload
        self.future = future
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        if self.transport is not None:
            self.transport.sendto(self.payload)

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        if not self.future.done():
            self.future.set_result(data)
        if self.transport is not None:
            self.transport.close()

    def error_received(self, exc: Exception) -> None:
        if not self.future.done():
            self.future.set_exception(exc)
        if self.transport is not None:
            self.transport.close()

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc is not None and not self.future.done():
            self.future.set_exception(exc)


class DNSResolver:
    def __init__(self, config: Config, logger: logging.Logger) -> None:
        self.config = config
        self.logger = logger

    async def query_upstream(self, raw_request: bytes, timeout: float = 3.0) -> Optional[bytes]:
        if not raw_request or len(raw_request) > 4096:
            return None
        loop = asyncio.get_running_loop()
        for attempt in range(self.config.retry_count):
            fut: asyncio.Future[bytes] = loop.create_future()
            transport: Optional[asyncio.DatagramTransport] = None
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: _UdpQueryClientProtocol(raw_request, fut),
                    remote_addr=(self.config.upstream_dns_host, self.config.upstream_dns_port),
                )
                return await asyncio.wait_for(fut, timeout=timeout)
            except (asyncio.TimeoutError, OSError) as exc:
                self.logger.warning(
                    "Upstream DNS query attempt %d/%d failed: %s",
                    attempt + 1,
                    self.config.retry_count,
                    exc,
                )
                if attempt + 1 < self.config.retry_count:
                    await asyncio.sleep(0.2 * (2 ** attempt))
            finally:
                if transport is not None:
                    transport.close()
        return None

    async def resolve_upstream_a(self, hostname: str) -> str:
        clean_host = hostname.strip().rstrip(".").lower()
        try:
            socket.inet_aton(clean_host)
            return clean_host
        except OSError:
            pass

        q = DNSRecord.question(clean_host, "A")
        raw_resp = await self.query_upstream(q.pack())
        if raw_resp:
            try:
                parsed = DNSRecord.parse(raw_resp)
                for rr in parsed.rr:
                    if rr.rtype == QTYPE.A:
                        return str(rr.rdata)
            except dnslib.DNSError as exc:
                self.logger.error("Failed to parse upstream DNS response for %s: %s", clean_host, exc)
        raise RuntimeError(f"Could not resolve A record for {clean_host}")

    async def handle_dns_packet(self, data: bytes) -> Optional[bytes]:
        if not data or len(data) < 12 or len(data) > 4096:
            return None
        try:
            request = DNSRecord.parse(data)
        except Exception as exc:
            self.logger.debug("Malformed DNS packet: %s", exc)
            return None

        if len(request.questions) == 0:
            reply = request.reply()
            reply.header.rcode = RCODE.FORMERR
            return reply.pack()

        qname = str(request.q.qname).rstrip(".").lower()
        qtype = request.q.qtype

        if qname in INTERCEPTED_DOMAINS:
            reply = request.reply()
            if qtype in (QTYPE.A, QTYPE.ANY):
                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(self.config.target_ip), ttl=60))
            return reply.pack()

        upstream_resp = await self.query_upstream(data)
        if upstream_resp is not None:
            return upstream_resp

        reply = request.reply()
        reply.header.rcode = RCODE.SERVFAIL
        return reply.pack()


class DNSUdpServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, resolver: DNSResolver) -> None:
        self.resolver = resolver
        self.transport: Optional[asyncio.DatagramTransport] = None
        self._tasks: set[asyncio.Task[None]] = set()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        task = asyncio.create_task(self._process(data, addr))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _process(self, data: bytes, addr: Tuple[str, int]) -> None:
        resp = await self.resolver.handle_dns_packet(data)
        if resp and self.transport is not None:
            try:
                self.transport.sendto(resp, addr)
            except OSError as exc:
                self.resolver.logger.error("Failed to send DNS UDP reply to %s: %s", addr, exc)


async def handle_dns_tcp(
    resolver: DNSResolver, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    try:
        len_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=5.0)
        msg_len = struct.unpack("!H", len_bytes)[0]
        if msg_len == 0 or msg_len > 4096:
            return
        data = await asyncio.wait_for(reader.readexactly(msg_len), timeout=5.0)
        resp = await resolver.handle_dns_packet(data)
        if resp:
            writer.write(struct.pack("!H", len(resp)) + resp)
            await asyncio.wait_for(writer.drain(), timeout=5.0)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
        return
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


def build_server_ssl_context(cert_file: Path, key_file: Path) -> ssl.SSLContext:
    if not cert_file.is_file():
        raise FileNotFoundError(f"SSL certificate not found: {cert_file}")
    if not key_file.is_file():
        raise FileNotFoundError(f"SSL key not found: {key_file}")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["http/1.1"])
    ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    return ctx


def build_upstream_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


class QuasarServer:
    def __init__(
        self,
        config: Config,
        resolver: DNSResolver,
        access_logger: logging.Logger,
        error_logger: logging.Logger,
        upstream_ssl: Optional[ssl.SSLContext] = None,
        upstream_port: int = 443,
    ) -> None:
        self.config = config
        self.resolver = resolver
        self.access_logger = access_logger
        self.error_logger = error_logger
        self.upstream_ssl = upstream_ssl or build_upstream_ssl_context()
        self.upstream_port = upstream_port
        self.http_client = httpx.AsyncClient(
            verify=self.upstream_ssl,
            http2=False,
            timeout=httpx.Timeout(config.proxy_timeout, connect=10.0),
            follow_redirects=False,
        )

    async def close(self) -> None:
        await self.http_client.aclose()

    def create_http_app(self) -> web.Application:
        app = web.Application(client_max_size=self.config.max_body_size)
        app.router.add_route("*", "/generate_204", self.handle_generate_204)
        app.router.add_route("*", "/{tail:.*}", self.handle_http_redirect)
        return app

    def create_https_app(self) -> web.Application:
        app = web.Application(client_max_size=self.config.max_body_size)
        app.router.add_route("*", "/generate_204", self.handle_generate_204)
        app.router.add_route("*", "/get_sync_info", self.handle_get_sync_info)
        app.router.add_route("*", "/check_updates", self.handle_check_updates)
        app.router.add_route("*", "/{tail:.*}", self.handle_https_proxy)
        return app

    def _log_access(self, request: web.Request, status: int) -> None:
        remote = request.remote or "-"
        host = request.headers.get("Host", "-")
        self.access_logger.info('%s "%s %s" %d Host=%s', remote, request.method, request.raw_path, status, host)

    async def handle_generate_204(self, request: web.Request) -> web.Response:
        self._log_access(request, 204)
        return web.Response(status=204)

    async def handle_http_redirect(self, request: web.Request) -> web.Response:
        host = request.headers.get("Host", "").strip()
        if not host:
            self._log_access(request, 400)
            return web.Response(status=400, text="Missing Host header")
        hostname = host.split(":")[0]
        target_url = f"https://{hostname}{request.raw_path}"
        self._log_access(request, 301)
        return web.Response(status=301, headers={"Location": target_url})

    async def handle_get_sync_info(self, request: web.Request) -> web.Response:
        self._log_access(request, 200)
        return web.Response(
            status=200,
            text=SYNC_INFO_PAYLOAD,
            content_type="application/json",
        )

    async def handle_check_updates(self, request: web.Request) -> web.Response:
        self._log_access(request, 200)
        return web.Response(
            status=200,
            text=CHECK_UPDATES_PAYLOAD,
            content_type="application/json",
        )

    async def handle_https_proxy(self, request: web.Request) -> web.StreamResponse:
        host_header = request.headers.get("Host", "").strip()
        if not host_header:
            self._log_access(request, 400)
            return web.Response(status=400, text="Missing Host header")

        hostname = host_header.split(":")[0].strip().lower()
        if not hostname:
            self._log_access(request, 400)
            return web.Response(status=400, text="Invalid Host header")

        try:
            upstream_ip = await self.resolver.resolve_upstream_a(hostname)
        except Exception as exc:
            self.error_logger.error("DNS resolution failed for upstream %s: %s", hostname, exc)
            self._log_access(request, 502)
            return web.Response(status=502, text="Bad Gateway")

        upgrade_hdr = request.headers.get("Upgrade", "")
        if upgrade_hdr.lower() == "websocket":
            return await self._proxy_websocket(request, hostname, host_header, upstream_ip)

        return await self._proxy_http_request(request, hostname, host_header, upstream_ip)

    async def _proxy_http_request(
        self, request: web.Request, hostname: str, host_header: str, upstream_ip: str
    ) -> web.Response:
        try:
            body = await request.read()
        except web.HTTPRequestEntityTooLarge:
            self._log_access(request, 413)
            return web.Response(status=413, text="Payload Too Large")
        except Exception as exc:
            self.error_logger.error("Error reading client request body: %s", exc)
            self._log_access(request, 400)
            return web.Response(status=400, text="Bad Request")

        remote_addr = request.remote or "127.0.0.1"
        hop_by_hop = {
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
        }
        headers = {k: v for k, v in request.headers.items() if k.lower() not in hop_by_hop}
        headers["Host"] = host_header
        headers["X-Forwarded-Proto"] = "https"
        headers["X-Forwarded-For"] = remote_addr
        headers["X-Real-IP"] = remote_addr

        port_suffix = f":{self.upstream_port}" if self.upstream_port != 443 else ""
        target_url = f"https://{upstream_ip}{port_suffix}{request.raw_path}"

        last_exc: Optional[Exception] = None
        for attempt in range(self.config.retry_count):
            try:
                resp = await self.http_client.request(
                    method=request.method,
                    url=target_url,
                    headers=headers,
                    content=body,
                    extensions={"sni_hostname": hostname},
                )
                resp_headers = {
                    k: v
                    for k, v in resp.headers.items()
                    if k.lower() not in hop_by_hop and k.lower() != "content-encoding" and k.lower() != "content-length"
                }
                self._log_access(request, resp.status_code)
                return web.Response(
                    status=resp.status_code,
                    headers=resp_headers,
                    body=resp.content,
                )
            except httpx.HTTPError as exc:
                last_exc = exc
                self.error_logger.warning(
                    "Upstream HTTP proxy attempt %d/%d for %s failed: %s",
                    attempt + 1,
                    self.config.retry_count,
                    hostname,
                    exc,
                )
                if attempt + 1 < self.config.retry_count:
                    await asyncio.sleep(0.2 * (2 ** attempt))

        self.error_logger.error("All proxy attempts failed for %s: %s", hostname, last_exc)
        self._log_access(request, 502)
        return web.Response(status=502, text="Bad Gateway")

    async def _proxy_websocket(
        self, request: web.Request, hostname: str, host_header: str, upstream_ip: str
    ) -> web.StreamResponse:
        ws_server = web.WebSocketResponse(max_msg_size=self.config.max_body_size, heartbeat=30.0)
        await ws_server.prepare(request)

        remote_addr = request.remote or "127.0.0.1"
        ws_headers = {
            "Host": host_header,
            "X-Forwarded-For": remote_addr,
            "X-Real-IP": remote_addr,
        }
        for k, v in request.headers.items():
            if k.lower() in ("authorization", "cookie", "user-agent", "x-ya-service-ticket"):
                ws_headers[k] = v

        port_suffix = f":{self.upstream_port}" if self.upstream_port != 443 else ""
        ws_url = f"wss://{upstream_ip}{port_suffix}{request.raw_path}"
        timeout = aiohttp.ClientTimeout(total=None, sock_read=self.config.proxy_timeout)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.ws_connect(
                    ws_url,
                    headers=ws_headers,
                    ssl=self.upstream_ssl,
                    server_hostname=hostname,
                    max_msg_size=self.config.max_body_size,
                ) as ws_client:
                    self._log_access(request, 101)

                    async def client_to_upstream() -> None:
                        async for msg in ws_server:
                            if msg.type == aiohttp.WSMsgType.TEXT:
                                await ws_client.send_str(msg.data)
                            elif msg.type == aiohttp.WSMsgType.BINARY:
                                await ws_client.send_bytes(msg.data)
                            elif msg.type == aiohttp.WSMsgType.CLOSE:
                                await ws_client.close()
                                break
                            elif msg.type == aiohttp.WSMsgType.ERROR:
                                break

                    async def upstream_to_client() -> None:
                        async for msg in ws_client:
                            if msg.type == aiohttp.WSMsgType.TEXT:
                                await ws_server.send_str(msg.data)
                            elif msg.type == aiohttp.WSMsgType.BINARY:
                                await ws_server.send_bytes(msg.data)
                            elif msg.type == aiohttp.WSMsgType.CLOSE:
                                await ws_server.close()
                                break
                            elif msg.type == aiohttp.WSMsgType.ERROR:
                                break

                    tasks = [
                        asyncio.create_task(client_to_upstream()),
                        asyncio.create_task(upstream_to_client()),
                    ]
                    _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    for p in pending:
                        p.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)
        except Exception as exc:
            self.error_logger.error("WebSocket proxy error for %s: %s", hostname, exc)
        finally:
            if not ws_server.closed:
                await ws_server.close()

        return ws_server


async def run_services(config: Config) -> None:
    access_logger, error_logger = setup_loggers(config)
    ssl_ctx = build_server_ssl_context(config.cert_file, config.key_file)
    resolver = DNSResolver(config, error_logger)
    quasar = QuasarServer(config, resolver, access_logger, error_logger)

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    udp_transport, _ = await loop.create_datagram_endpoint(
        lambda: DNSUdpServerProtocol(resolver),
        local_addr=(config.bind_ip, config.dns_port),
    )
    tcp_dns_server = await asyncio.start_server(
        lambda r, w: handle_dns_tcp(resolver, r, w),
        host=config.bind_ip,
        port=config.dns_port,
    )

    http_runner = web.AppRunner(quasar.create_http_app(), access_log=None)
    await http_runner.setup()
    http_site = web.TCPSite(http_runner, host=config.bind_ip, port=config.http_port)
    await http_site.start()

    https_runner = web.AppRunner(quasar.create_https_app(), access_log=None)
    await https_runner.setup()
    https_site = web.TCPSite(https_runner, host=config.bind_ip, port=config.https_port, ssl_context=ssl_ctx)
    await https_site.start()

    error_logger.info(
        "Started DNS on %s:%d (target=%s), HTTP on %s:%d, HTTPS on %s:%d",
        config.bind_ip,
        config.dns_port,
        config.target_ip,
        config.bind_ip,
        config.http_port,
        config.bind_ip,
        config.https_port,
    )

    try:
        await stop_event.wait()
    finally:
        error_logger.info("Shutting down services...")
        udp_transport.close()
        tcp_dns_server.close()
        await tcp_dns_server.wait_closed()
        await http_runner.cleanup()
        await https_runner.cleanup()
        await quasar.close()


def main() -> None:
    try:
        config = Config.from_env()
        asyncio.run(run_services(config))
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        sys.stderr.write(f"Fatal startup error: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()