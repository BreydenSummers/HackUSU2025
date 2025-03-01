from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from .models import Team, Product
from django.contrib.auth import authenticate, login, logout, get_user_model
import requests, json

url = "http://127.0.0.1:5000"

def is_admin(user):
    return user.is_staff or user.is_superuser

def is_player(user):
    return not user.is_staff

def index(request):
    """index page view"""
    return render(request, "simulation/index.html")


def login_page(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            print(user)
            if user.is_staff:
                return redirect("admin_dashboard")
            return redirect("home")
    return render(request, "simulation/login.html")

def logout_view(request):
    logout(request)
    return redirect("home")

@login_required(redirect_field_name=None,login_url="login")
@user_passes_test(is_player,"home",redirect_field_name=None)
def shop(request):
    """Shop page view"""
    if request.method == "POST":
        if "purchase" in request.POST:
            print(request.POST)
    try:
        response = requests.get(f"{url}/get_upgrades?id=0")
        data = json.loads(response.text)
    except Exception:
        data = []
    return render(request, "simulation/shop.html", {"products": data})

@login_required(redirect_field_name=None,login_url="login")
@user_passes_test(is_player,"home",redirect_field_name=None)
def messages_dashboard(request):
    return render(request, "simulation/messages.html")

@login_required(redirect_field_name=None,login_url="login")
@user_passes_test(is_admin)
def admin_dashboard(request):
    """Admin dashboard view (for non-Django admin)"""
    if request.method == "POST":
        try:
            if "team-delete" in request.POST:
                to_delete = Team.objects.get(name=request.POST['team'])
                to_delete.delete()
            if "user-delete" in request.POST:
                to_delete = get_user_model().objects.get(username=request.POST['username'])
                to_delete.delete()
        except Exception as e:
            print(e)
    teams = Team.objects.filter(created_by=request.user)
    User = get_user_model()
    users = [u for u in User.objects.all() if not u.is_superuser and not u.is_staff]
    return render(request, "simulation/admin_dashboard.html", {"teams": teams, "players":users})


@login_required(redirect_field_name=None,login_url="login")
@user_passes_test(is_admin)
def create_team(request):
    """View for admin to create a team"""
    if request.method == "POST":
        # Process form data here (you'd use a form in a real app)
        name = request.POST.get("name")
        description = request.POST.get("description")

        team = Team(name=name, description=description, created_by=request.user)
        team.save()

        messages.success(request, f"Team '{name}' created successfully!")
        return redirect("admin_dashboard")

    return render(request, "simulation/create_team.html")

@login_required(redirect_field_name=None,login_url="login")
@user_passes_test(is_admin)
def add_user(request):
    teams = Team.objects.filter(created_by=request.user)
    if request.method == "POST":
        username = request.POST.get("username")
        firstname = request.POST.get("firstname")
        lastname = request.POST.get("lastname")
        password = request.POST.get("password")
        user = get_user_model().objects.create_user(username=username,
                                                    password=password,
                                                    first_name=firstname,
                                                    last_name=lastname)
        team = request.POST.get("team")
        for t in teams:
            if t.name == team:
                t.members.add(user)
        return redirect("admin_dashboard")
    return render(request, "simulation/add_user.html",{"teams": teams})