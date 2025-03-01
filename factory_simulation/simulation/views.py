from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from .models import Team, Product


def is_admin(user):
    return user.is_staff or user.is_superuser


def home(request):
    """Home page view"""
    return render(request, "simulation/home.html")


def shop(request):
    """Shop page view"""
    products = Product.objects.all()
    return render(request, "simulation/shop.html", {"products": products})


@login_required
@user_passes_test(is_admin)
def admin_dashboard(request):
    """Admin dashboard view (for non-Django admin)"""
    teams = Team.objects.filter(created_by=request.user)
    return render(request, "simulation/admin_dashboard.html", {"teams": teams})


@login_required
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

