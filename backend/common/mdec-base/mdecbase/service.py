import argparse
import tempfile
import traceback
from typing import Callable, Type

from aiohttp import web
import aiohttp


class Service:
    """
    Decompiler as a service
    """

    def __init__(self):
        self.app = web.Application()
        self.app.add_routes([web.post('/decompile', self.post_decompile),
                             web.get('/decompile/version',
                                     self.get_decompiler_version),
                             web.post('/ir', self.post_ir),
                             web.get('/ir/version', self.get_ir_version)])

    def decompile(self, path: str) -> str:
        raise NotImplementedError()

    def ir(self, path: str) -> str:
        raise NotImplementedError()

    def version(self) -> str:
        raise NotImplementedError()

    def ir_version(self) -> str:
        return self.version()

    @staticmethod
    async def __process_file(request: aiohttp.web.BaseRequest, callback: Callable[[str], str]) -> web.Response:
        reader = await request.multipart()
        binary = await reader.next()
        if binary is None:
            return web.Response(status=400)

        with tempfile.NamedTemporaryFile() as f:
            while True:
                chunk = await binary.read_chunk()
                if not chunk:
                    break
                f.write(chunk)
                f.flush()

            try:
                output = callback(f.name)
                resp_status = 200
            except:
                output = traceback.format_exc()
                resp_status = 500

            return web.Response(text=output, status=resp_status)

    async def post_decompile(self, request: aiohttp.web.BaseRequest) -> web.Response:
        return await Service.__process_file(request, self.decompile)

    async def post_ir(self, request: aiohttp.web.BaseRequest) -> web.Response:
        return await Service.__process_file(request, self.ir)

    async def _get_version(self, callback: Callable[[], str]) -> web.Response:
        try:
            version = callback()
            resp_status = 200
        except:
            version = traceback.format_exc()
            resp_status = 500
        return web.Response(text=version, status=resp_status)

    async def get_decompiler_version(self, _request: aiohttp.web.BaseRequest) -> web.Response:
        return await self._get_version(self.version)

    async def get_ir_version(self, _request: aiohttp.web.BaseRequest) -> web.Response:
        return await self._get_version(self.ir_version)


def mdec_main(service: Type[Service]):
    """
    Common module main function
    """
    ap = argparse.ArgumentParser()
    ap.add_argument('file', nargs='?',
                    help='If provided, decompile given file and exit. Otherwise, start server')
    args = ap.parse_args()

    s = service()
    if args.file:
        print(s.decompile(args.file))
    else:
        web.run_app(s.app, port=8000)
