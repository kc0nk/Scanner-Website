from __future__ import annotations

from abc import ABC, abstractmethod

from core.context import ExploitContext
from core.models import ExploitResult


class ExploitModule(ABC):
    name = "Unnamed"
    category = "misc"
    destructive = False

    @abstractmethod
    async def run(self, ctx: ExploitContext) -> ExploitResult:
        raise NotImplementedError
