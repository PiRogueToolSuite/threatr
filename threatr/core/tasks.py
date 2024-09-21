import logging

from django.utils import timezone

from threatr.core.loader import ModulesLoader
from threatr.core.models import Request, VendorCredentials
from threatr.modules.module import AnalysisModule

logger = logging.getLogger(__name__)


def launch_module(request: Request, handler) -> bool:
    credentials = VendorCredentials.objects.filter(vendor=handler.unique_identifier())
    if not credentials:
        logger.error(f"No credentials found for module {handler.unique_identifier()}")
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
    request.status = Request.Status.PROCESSING
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
