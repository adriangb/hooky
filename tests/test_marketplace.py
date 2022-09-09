import hashlib
import hmac

from src.settings import Settings

from .conftest import Client


def test_auth_ok_no_data(client: Client, settings: Settings):
    request_body = b'{}'
    digest = hmac.new(settings.marketplace_webhook_secret.get_secret_value(), request_body, hashlib.sha256).hexdigest()
    r = client.post('/marketplace/', data=request_body, headers={'x-hub-signature-256': f'sha256={digest}'})
    assert r.status_code == 202, r.text
    assert r.text == 'ok'


def test_auth_fails_no_header(client: Client, settings: Settings):
    request_body = b'{}'
    r = client.post('/marketplace/', data=request_body)
    assert r.status_code == 422, r.text
    assert r.json() == {
        'detail': [
            {
                'loc': ['header', 'x-hub-signature-256'],
                'msg': 'Missing required header parameter',
                'type': 'value_error',
            }
        ]
    }


def test_auth_fails_invalid_format(client: Client, settings: Settings):
    request_body = b'{}'
    r = client.post('/marketplace/', data=request_body, headers={'x-hub-signature-256': 'sha256=foobar'})
    assert r.status_code == 422, r.text
    assert r.json() == {
        'detail': [
            {
                'loc': ['header', 'x-hub-signature-256'],
                'msg': "string does not match regex \'sha256=[A-Fa-f0-9]{64}\'",
                'type': 'value_error.str.regex',
                'ctx': {'pattern': 'sha256=[A-Fa-f0-9]{64}'},
            }
        ]
    }


def test_auth_fails_invalid_signature(client: Client, settings: Settings):
    request_body = b'{}'
    digest = '6acf2b79c670dc7fba61b3d6257eea89f7e88c8681f04d34bce9fa95547a5c02'
    digest = hmac.new(
        settings.marketplace_webhook_secret.get_secret_value(), b'not the right body', hashlib.sha256
    ).hexdigest()
    r = client.post('/marketplace/', data=request_body, headers={'x-hub-signature-256': f'sha256={digest}'})
    assert r.status_code == 403, r.text
    assert r.json() == {'detail': 'Invalid marketplace signature'}
