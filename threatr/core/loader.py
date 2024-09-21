import importlib
import inspect
import logging
import pkgutil

from threatr.core.models import Request
from threatr.modules.module import AnalysisModule

logger = logging.getLogger(__name__)


class ModulesLoader:
    root_module = importlib.import_module("threatr.modules")
    module_classes: set[type[AnalysisModule]] = set()
    supported_types = {}

    def list_modules(self) -> set[type[AnalysisModule]]:
        for _, modname, _ in pkgutil.walk_packages(
            path=self.root_module.__path__,
            prefix=self.root_module.__name__ + ".",
            onerror=lambda x: None,
        ):
            module = importlib.import_module(modname)
            for name in dir(module):
                obj = getattr(module, name)
                if (
                    inspect.isclass(obj)
                    and issubclass(obj, AnalysisModule)
                    and not inspect.isabstract(obj)
                ):
                    self.module_classes.add(obj)
        return self.module_classes

    def get_supported_types(self) -> dict[str, list[str]]:
        if not self.module_classes:
            self.list_modules()
        self.supported_types = {}
        for module in self.module_classes:
            for st, t in module.supported_types().items():
                if st not in self.supported_types:
                    self.supported_types[st] = set()
                self.supported_types[st].update(t)
        for st, t in self.supported_types.items():
            self.supported_types[st] = list(t)
        return self.supported_types


    def get_candidate_classes(self, request: Request) -> {type}:
        candidates = set()
        if not self.module_classes:
            self.list_modules()
        for c in self.module_classes:
            logger.info(f"Loading analysis module {c} for [{c.vendor()}]")
            requested_super_type = request.super_type.short_name.lower()
            requested_type = request.type.short_name.lower()
            supported_types = c.supported_types()
            if requested_type in supported_types.get(requested_super_type, []):  # noqa: E501
                candidates.add(c)
        return candidates
