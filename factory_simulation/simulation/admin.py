from django.contrib import admin
from .models import Team, TeamMembership, Product


class TeamMembershipInline(admin.TabularInline):
    model = TeamMembership
    extra = 1


@admin.register(Team)
class TeamAdmin(admin.ModelAdmin):
    list_display = ("name", "created_by", "created_at")
    search_fields = ("name", "created_by__username")
    inlines = [TeamMembershipInline]

    def save_model(self, request, obj, form, change):
        if not change:  # If creating a new team
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ("name", "price")
    search_fields = ("name",)

