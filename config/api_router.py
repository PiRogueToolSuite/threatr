from django.conf import settings
from rest_framework.routers import DefaultRouter, SimpleRouter

from threatr.core.api.generic import RequestView, TypesView, ModulesView, StatusView

if settings.DEBUG:
    router = DefaultRouter()
else:
    router = SimpleRouter()

# router.register("users", UserViewSet)
router.register("request", RequestView, basename='request')
router.register("modules", ModulesView, basename='modules')
router.register("status", StatusView, basename='status')
router.register("types", TypesView, basename='types')

app_name = "api"
urlpatterns = router.urls
