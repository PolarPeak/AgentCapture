import shutil
from pathlib import Path

from fastapi import UploadFile

from app.core.config import get_settings

settings = get_settings()
ROOT = settings.knowledge_base_root_path


def ensure_root() -> Path:
    ROOT.mkdir(parents=True, exist_ok=True)
    return ROOT


def safe_path(relative_path: str = "") -> Path:
    root = ensure_root()
    candidate = (root / relative_path).resolve()
    candidate.relative_to(root)
    return candidate


def list_directory(relative_path: str = "") -> dict:
    current = safe_path(relative_path)
    directories: list[dict] = []
    files: list[dict] = []
    for child in sorted(current.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
        item = {
            "name": child.name,
            "path": str(child.relative_to(ensure_root())),
            "is_dir": child.is_dir(),
        }
        if child.is_dir():
            directories.append(item)
        else:
            item["size"] = child.stat().st_size
            files.append(item)
    return {
        "root": str(ensure_root()),
        "current": str(current.relative_to(ensure_root())) if current != ensure_root() else "",
        "directories": directories,
        "files": files,
    }


async def save_upload(relative_path: str, upload: UploadFile) -> Path:
    current = safe_path(relative_path)
    current.mkdir(parents=True, exist_ok=True)
    target = safe_path(str(Path(relative_path) / upload.filename))
    with target.open("wb") as handle:
        while chunk := await upload.read(1024 * 1024):
            handle.write(chunk)
    return target


def make_directory(relative_path: str, name: str) -> Path:
    target = safe_path(str(Path(relative_path) / name))
    target.mkdir(parents=True, exist_ok=True)
    return target


def rename_entry(relative_path: str, new_name: str) -> Path:
    source = safe_path(relative_path)
    target = safe_path(str(Path(relative_path).parent / new_name))
    source.rename(target)
    return target


def delete_entry(relative_path: str) -> None:
    target = safe_path(relative_path)
    if target.is_dir():
        shutil.rmtree(target)
    elif target.exists():
        target.unlink()
