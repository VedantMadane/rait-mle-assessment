from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class SupplierAdapter(ABC):
    supplier_name: str

    @abstractmethod
    def load(self, path: str) -> list[dict[str, Any]]:
        """Return raw-normalized dicts; use ingest_records for Pydantic validation."""
        raise NotImplementedError
