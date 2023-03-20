from django.contrib import admin

from threatr.core.models import Entity, EntitySuperType, EntityType, Request, Event, EntityRelation, VendorCredentials


class RequestAdmin(admin.ModelAdmin):
    list_display = ('value', 'super_type', 'type')
    list_filter = ('value', 'super_type', 'type')
admin.site.register(Request, RequestAdmin)


class EntityAdmin(admin.ModelAdmin):
    list_display = ('type', 'name', 'description')
    list_filter = ('super_type',)
admin.site.register(Entity, EntityAdmin)


class EntityRelationAdmin(admin.ModelAdmin):
    list_display = ('name', 'obj_from', 'obj_to')
    list_filter = ('name', 'obj_from', 'obj_to')
admin.site.register(EntityRelation, EntityRelationAdmin)


class EventAdmin(admin.ModelAdmin):
    list_display = ('name', 'involved_entity', 'type')
    list_filter = ('name', 'involved_entity')
admin.site.register(Event, EventAdmin)


class EntitySuperTypeAdmin(admin.ModelAdmin):
    list_display = ('short_name', 'name', 'description')
    list_filter = ('name', 'description')
admin.site.register(EntitySuperType, EntitySuperTypeAdmin)


class EntityTypeAdmin(admin.ModelAdmin):
    list_display = ('short_name', 'name', 'description')
    list_filter = ('name', 'description')
admin.site.register(EntityType, EntityTypeAdmin)


class VendorCredentialsAdmin(admin.ModelAdmin):
    list_display = ('vendor',)
    list_filter = ('vendor',)
admin.site.register(VendorCredentials, VendorCredentialsAdmin)
