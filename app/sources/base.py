from __future__ import annotations

from abc import ABC, abstractmethod

from typing import Literal

from app.models.report import AddressReport, Chain


class Source(ABC):
    name: str
    chain: Chain | Literal["multi"]

    @abstractmethod
    async def fetch(self, address: str) -> AddressReport:
        raise NotImplementedError

