from django.conf import settings
from django.db import transaction
from django.db.models import Q, QuerySet
from django.http import JsonResponse, HttpResponse
from django_q.tasks import async_task
from django_q.status import Stat
from rest_framework import mixins, status
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from threatr.core.api.serializers import (
    RequestSerializer,
    EntitySerializer,
    EventSerializer,
    EntityRelationSerializer,
    FullEntitySuperTypeSerializer,
)
from threatr.core.loader import ModulesLoader
from threatr.core.models import (
    Request,
    EntitySuperType,
    EntityType,
    Entity,
    Event,
    EntityRelation, VendorCredentials,
)
from threatr.core.tasks import handle_request


class TypesView(mixins.ListModelMixin, GenericViewSet):
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [IsAuthenticated]
    queryset = EntitySuperType.objects.all()
    serializer_class = FullEntitySuperTypeSerializer

    @action(methods=['get'], detail=False)
    def supported(self, _):
        ml = ModulesLoader()
        raw_supported_types = ml.get_supported_types()
        supported_models = []
        supported_types = {}
        for raw_super_type, raw_types in raw_supported_types.items():
            supported_models.append({'name': raw_super_type.title(), 'short_name': raw_super_type.upper()})
            supported_types[raw_super_type.upper()] = []
            for _type in sorted(raw_types):
                available_type = EntityType.get_types(raw_super_type.upper()).get(_type.upper())
                supported_types[raw_super_type.upper()].append({
                    'id': available_type.short_name,
                    'name': available_type.name,
                    'label': available_type.name,
                })
        return JsonResponse(
            {'super_types': supported_models, 'types': supported_types},
            status=status.HTTP_200_OK,
            json_dumps_params={'sort_keys': True})


class ModulesView(GenericViewSet):
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @staticmethod
    def get_module_list():
        ml = ModulesLoader()
        available_modules = []
        for module in ml.list_modules():
            credentials = VendorCredentials.objects.filter(vendor=module.unique_identifier()).count()
            available_modules.append({
                'id': module.unique_identifier(),
                'vendor': module.vendor(),
                'configured': credentials,
                'description': module.description(),
                'supported_types': module.supported_types()
            })
        return available_modules

    def list(self, _):
        return JsonResponse(ModulesView.get_module_list(), status=status.HTTP_200_OK, safe=False)


class StatusView(GenericViewSet):
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, _):
        commit_hash = ''
        # Undefined in dev mode
        try:
            commit_hash = settings.GIT_COMMIT_HASH
        except: pass  # noqa: E722, E701
        status_data = {
            'git_commit_hash': commit_hash,
            'available_modules': ModulesView.get_module_list(),
            'workers': [
                {
                    'id': stat.cluster_id,
                    'status': stat.status,
                    'uptime': stat.uptime(),
                    'enqueued_tasks': stat.task_q_size,
                    'available_results': stat.done_q_size,
                }
                for stat in Stat.get_all()
            ],
            'cached_entities': Entity.objects.count(),
            'cached_events': Event.objects.count(),
            'cached_relations': EntityRelation.objects.count()
        }
        return JsonResponse(status_data, status=status.HTTP_200_OK, safe=False)


class RequestView(
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
    mixins.ListModelMixin,
    GenericViewSet,
):
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [IsAuthenticated]
    queryset = Request.objects.all()
    serializer_class = RequestSerializer

    @staticmethod
    def __get_mermaid_graph(entities, relations):
        entity_lines = []
        relation_lines = []
        for entity in entities:
            entity_lines.append(f'{entity.id}("{str(entity)}")')
        for relation in relations:
            relation_lines.append(
                f"{relation.obj_from.id} -- {relation.name} --> {relation.obj_to.id}"
            )
        entity_txt = "\n\t".join(list(set(entity_lines)))
        relation_txt = "\n\t".join(list(set(relation_lines)))
        return f"flowchart LR\n\t{entity_txt}\n\t{relation_txt}"

    def __handle_existing_results(self, q_set: QuerySet, output_format: str):
        root_entity = q_set.first()
        events = Event.objects.filter(involved_entity=root_entity).all()
        relations = EntityRelation.objects.filter(
            Q(obj_from=root_entity) | Q(obj_to=root_entity)
        ).all()
        if output_format == "json":
            entity_serializer = EntitySerializer(root_entity)
            event_serializer = EventSerializer(events, many=True)
            relation_serializer = EntityRelationSerializer(relations, many=True)
            entities = []
            for relation in relations:
                if relation.obj_from != root_entity:
                    entities.append(relation.obj_from)
                else:
                    entities.append(relation.obj_to)
            for event in events:
                if event.involved_entity and event.involved_entity != root_entity:
                    entities.append(event.involved_entity)
            entities = list(set(entities))
            entities_serializer = EntitySerializer(entities, many=True)
            result = {
                "root_entity": entity_serializer.data,
                "entities": entities_serializer.data,
                "events": event_serializer.data,
                "relations": relation_serializer.data,
                "graph": self.__get_mermaid_graph(entities + [root_entity], relations),
            }
            return JsonResponse(result, status=status.HTTP_200_OK)
        return HttpResponse('Invalid format', status=status.HTTP_406_NOT_ACCEPTABLE)

    def create(self, request, *args, **kwargs):
        value = request.data.get("value", "")
        e_super_type = request.data.get("super_type", "")
        e_type = request.data.get("type", "")
        output_format = request.data.get("format", "json")
        force = request.data.get("force", False)
        if not value:
            return Response(
                {"error": "Requested value cannot be empty"},
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )
        try:
            e_super_type = EntitySuperType.objects.get(short_name=e_super_type.upper())
        except Exception:
            return Response(
                {"error": "Selected entity super type not supported"},
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )
        try:
            e_type = EntityType.objects.get(short_name=e_type.upper())
        except Exception:
            return Response(
                {"error": "Selected entity type not supported"},
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )

        # Check if the requested entity already exists
        if not force:
            q_set = Entity.objects.filter(
                name=value, super_type=e_super_type, type=e_type
            )
            if q_set:
                return self.__handle_existing_results(q_set, output_format)

        # Start analysis modules
        request_object = None
        if not force:
            # Get the latest corresponding request
            requests = Request.objects.filter(
                value=value,
                super_type=e_super_type,
                type=e_type,
            )
            if requests:
                request_object = requests.first()
        # No existing request
        if force or not request_object:
            request_object = Request(
                value=value,
                super_type=e_super_type,
                type=e_type,
            )
            request_object.save()

        if request_object.status == Request.Status.CREATED:
            request_object.status = Request.Status.ENQUEUED
            request_object.save()
            transaction.on_commit(lambda: async_task(handle_request, request_object.id))

        # Simply return the details of the request, client would have to come back later
        serializer = RequestSerializer(request_object)
        headers = self.get_success_headers(serializer.data)
        if request_object.status == Request.Status.FAILED:
            return Response(serializer.data, status=status.HTTP_404_NOT_FOUND)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )
