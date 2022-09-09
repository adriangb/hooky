from pydantic import BaseSettings, FilePath, RedisDsn, SecretBytes

__all__ = 'Settings', 'log'


class Settings(BaseSettings):
    github_app_id: str = '227243'
    github_app_secret_key: FilePath = 'github_app_secret_key.pem'
    webhook_secret: SecretBytes
    marketplace_webhook_secret: SecretBytes
    redis_dsn: RedisDsn = RedisDsn('localhost', scheme='redis', port='6379')
    config_cache_timeout: int = 600


def log(msg: str) -> None:
    print(msg, flush=True)
