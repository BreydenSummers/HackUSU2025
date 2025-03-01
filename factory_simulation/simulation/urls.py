from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("shop/", views.shop, name="shop"),
    path("admin-dashboard/", views.admin_dashboard, name="admin_dashboard"),
    path("create-team/", views.create_team, name="create_team"),
]
