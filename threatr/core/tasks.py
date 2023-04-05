import importlib
import inspect
import logging
import pkgutil

from django.utils import timezone

from threatr.core.models import Request, VendorCredentials
from threatr.modules.module import AnalysisModule

logger = logging.getLogger(__name__)


class ModulesLoader:
    root_module = importlib.import_module('threatr.modules')
    module_classes = set()

    def list_modules(self) -> {type}:
        for _, modname, _ in pkgutil.walk_packages(path=self.root_module.__path__,
                                                   prefix=self.root_module.__name__ + '.',
                                                   onerror=lambda x: None):
            module = importlib.import_module(modname)
            for name in dir(module):
                obj = getattr(module, name)
                if inspect.isclass(obj) and issubclass(obj, AnalysisModule) and not inspect.isabstract(obj):
                    self.module_classes.add(obj)
        return self.module_classes

    def get_candidate_classes(self, request: Request) -> {type}:
        candidates = set()
        if not self.module_classes:
            self.list_modules()
        for c in self.module_classes:
            logger.info(f'Loading analysis module {c} for [{c.vendor()}]')
            if request.super_type.short_name.lower() in c.handled_super_types() and request.type.short_name.lower() in c.handled_types():  # noqa: E501
                candidates.add(c)
        return candidates


def launch_module(request: Request, handler: type) -> bool:
    credentials = VendorCredentials.objects.filter(vendor=handler.unique_identifier())
    if not credentials:
        logger.error(f'No credentials found for module {handler.unique_identifier()}')
        return False

    # Rotate credentials
    module_credentials: VendorCredentials = credentials.first()
    module_credentials.last_usage = timezone.now()
    module_credentials.save()
    analysis_module: AnalysisModule = handler(request, module_credentials.credentials)

    if analysis_module.fail_fast():
        return False

    try:
        analysis_module.execute_request()
        analysis_module.save_results()
        return True
    except Exception as e:
        logger.exception(e)
        return False


def handle_request(request_id: str):
    request = Request.objects.get(id=request_id)
    request.status = Request.Status.SUCCEEDED
    request.save()
    loader = ModulesLoader()
    modules = loader.get_candidate_classes(request)
    success = False
    for module in modules:
        success |= launch_module(request, module)
    if success:
        request.status = Request.Status.SUCCEEDED
    else:
        request.status = Request.Status.FAILED
    request.save()
