"""Object storage for uploads. Content is always AES-GCM encrypted by the application before it is stored."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Protocol

from app.core.crypto import get_keyring


class ObjectStore(Protocol):
    async def put(self, key: str, data: bytes) -> None: ...
    async def get(self, key: str) -> bytes: ...
    async def delete(self, key: str) -> None: ...


class LocalStore:
    def __init__(self, root: str) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        p = (self.root / key).resolve()
        if not str(p).startswith(str(self.root)):
            raise ValueError("invalid storage key")
        return p

    async def put(self, key: str, data: bytes) -> None:
        p = self._path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        await asyncio.to_thread(p.write_bytes, data)

    async def get(self, key: str) -> bytes:
        return await asyncio.to_thread(self._path(key).read_bytes)

    async def delete(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)


class S3Store:
    def __init__(self, bucket: str, endpoint_url: str | None, region: str | None) -> None:
        import boto3

        self._bucket = bucket
        self._s3 = boto3.client("s3", endpoint_url=endpoint_url, region_name=region)

    async def put(self, key: str, data: bytes) -> None:
        await asyncio.to_thread(self._s3.put_object, Bucket=self._bucket, Key=key, Body=data)

    async def get(self, key: str) -> bytes:
        obj = await asyncio.to_thread(self._s3.get_object, Bucket=self._bucket, Key=key)
        return obj["Body"].read()

    async def delete(self, key: str) -> None:
        await asyncio.to_thread(self._s3.delete_object, Bucket=self._bucket, Key=key)


_store: ObjectStore | None = None


def get_store() -> ObjectStore:
    global _store
    if _store is None:
        from app.core.config import get_settings

        s = get_settings()
        if s.storage_backend == "s3":
            if not s.s3_bucket:
                raise RuntimeError("TR_S3_BUCKET is required for the s3 storage backend")
            _store = S3Store(s.s3_bucket, s.s3_endpoint_url, s.s3_region)
        else:
            _store = LocalStore(s.storage_local_path)
    return _store


async def put_encrypted(key: str, data: bytes) -> None:
    await get_store().put(key, get_keyring().encrypt(data, associated_data=key.encode()))


async def get_decrypted(key: str) -> bytes:
    return get_keyring().decrypt(await get_store().get(key), associated_data=key.encode())
