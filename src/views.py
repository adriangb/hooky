import hashlib
import hmac
import json
import os
import pathlib
from typing import Annotated

import anyio
from pydantic import Field
from xpresso import Depends, FromFile, FromHeader, HTTPException, Path
from xpresso.responses import FileResponse, HTMLResponse, PlainTextResponse

from .logic import process_event
from .settings import Settings, log

THIS_DIR = pathlib.Path(__file__).parent

CachedSettings = Annotated[Settings, Depends(Settings, scope='app')]  # type: ignore


def index_content() -> str:
    index_content = (THIS_DIR / 'index.html').read_text()
    commit = os.getenv('RENDER_GIT_COMMIT', '???')
    return index_content.replace('{{ COMMIT }}', commit).replace('{{ SHORT_COMMIT }}', commit[:7])


def index(content: Annotated[str, Depends(index_content, scope='app', sync_to_thread=True)]):
    return HTMLResponse(content=content)


def favicon():
    return FileResponse(THIS_DIR / 'favicon.ico')


SHA256Header = Annotated[str, Field(regex=r'sha256=[A-Fa-f0-9]{64}')]


def load_settings() -> Settings:
    return Settings()  # type: ignore


async def webhook(
    request_body: FromFile[bytes], x_hub_signature_256: FromHeader[SHA256Header], settings: CachedSettings
):
    digest = hmac.new(settings.webhook_secret.get_secret_value(), request_body, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(f'sha256={digest}', x_hub_signature_256):
        log(f'Invalid signature: {digest=} {x_hub_signature_256=}')
        raise HTTPException(status_code=403, detail='Invalid signature')

    action_taken, message = await anyio.to_thread.run_sync(
        lambda: process_event(request_body=request_body, settings=settings)
    )
    message = message if action_taken else f'{message}, no action taken'
    log(message)
    return PlainTextResponse(message, status_code=200 if action_taken else 202)


async def marketplace_webhook(
    request_body: FromFile[bytes], x_hub_signature_256: FromHeader[SHA256Header], settings: CachedSettings
):
    # this endpoint doesn't actually do anything, it's here in case we want to use it in future

    secret = settings.marketplace_webhook_secret
    if secret is None:
        raise HTTPException(status_code=403, detail='Marketplace secret not set')

    digest = hmac.new(secret.get_secret_value(), request_body, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(f'sha256={digest}', x_hub_signature_256):
        log(f'Invalid marketplace signature: {digest=} {x_hub_signature_256=}')
        raise HTTPException(status_code=403, detail='Invalid marketplace signature')

    body = json.loads(request_body)
    log(f'Marketplace webhook: { json.dumps(body, indent=2)}')
    return PlainTextResponse('ok', status_code=202)


views = [
    Path('/', get=index, head=index, post=webhook),
    Path('/favicon.ico', get=favicon, head=favicon),
    Path('/marketplace/', post=marketplace_webhook),
]
