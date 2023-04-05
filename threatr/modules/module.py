from abc import ABC, abstractmethod

from threatr.core.models import Request, Entity, EntityRelation, Event


class AnalysisModule(ABC):
    @classmethod
    @abstractmethod
    def vendor(cls) -> str:
        pass

    @classmethod
    @abstractmethod
    def unique_identifier(cls) -> str:
        pass

    @classmethod
    @abstractmethod
    def description(cls) -> str:
        pass

    @classmethod
    @abstractmethod
    def handled_types(cls) -> [str]:
        pass

    @classmethod
    @abstractmethod
    def handled_super_types(cls) -> [str]:
        pass

    @abstractmethod
    def __init__(self, request: Request):
        pass

    @abstractmethod
    def fail_fast(self) -> bool:
        pass

    @abstractmethod
    def execute_request(self):
        pass

    @abstractmethod
    def save_results(self):
        pass

    @abstractmethod
    def get_results(self) -> ([Entity], [EntityRelation], [Event]):
        pass
