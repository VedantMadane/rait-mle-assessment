from __future__ import annotations

from abc import ABC, abstractmethod

from src.schema.models import InteractionRecord


class SupplierAdapter(ABC):
    supplier_name: str

    @abstractmethod
    def load(self, path: str) -> list[InteractionRecord]:
        raise NotImplementedError
