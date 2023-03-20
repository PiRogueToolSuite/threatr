from django.conf import settings
from rest_framework.routers import DefaultRouter, SimpleRouter

from threatr.core.api.generic import RequestView, TypesView
from threatr.users.api.views import UserViewSet

if settings.DEBUG:
    router = DefaultRouter()
else:
    router = SimpleRouter()

router.register("users", UserViewSet)
router.register("request", RequestView)
router.register("types", TypesView)

app_name = "api"
urlpatterns = router.urls
