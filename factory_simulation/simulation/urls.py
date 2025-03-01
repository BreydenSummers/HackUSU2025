from django.urls import path
from . import views

urlpatterns = [
    path("dashboard", views.index, name="index"),
    path("shop/", views.shop, name="shop"),
    path("admin-dashboard/", views.admin_dashboard, name="admin_dashboard"),
    path("create-team/", views.create_team, name="create_team"),
    path("messages/",views.messages_dashboard, name="messages"),
    path("login/", views.login_page, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("add-user/", views.add_user, name="add_user"),
    path("send_message/", views.send_message, name="send_message"),
    path("start_game/", views.start_game, name="start_game"),
    path("end_game/", views.end_game, name="end_game"),
    path("send_attack/", views.send_attack, name="send_attack"),
    path("get-cycle/", views.get_cycle, name="get-cycle"),
    path("", views.home, name="home"),
]
