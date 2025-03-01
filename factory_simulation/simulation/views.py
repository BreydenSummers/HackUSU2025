from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from .models import Team, Product
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.http import JsonResponse
import requests, json
import os

url = "http://127.0.0.1:5000"
wazuh_port=5601

def is_admin(user):
    return user.is_staff or user.is_superuser

def is_player(user):
    return not user.is_staff

def get_team_by_user(user):
    teams = Team.objects.all()
    for t in teams:
        if user in t.members.all():
            return t
        
def check_teams():
    teams = Team.objects.all()
    try:
        response = requests.get(f"{url}/get_teams")
        flask_teams = json.loads(response.text)
        flask_teams = flask_teams['teams']
        for t in teams:
            if t.name not in flask_teams:
                try:
                    response = requests.get(f"{url}/add_team?team_id={t.name}")
                except Exception as e:
                    print("Error:",e)
    except Exception as e:
        print(e)

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
    check_teams()
    team = get_team_by_user(request.user)
    if request.method == "POST":
        if "purchase" in request.POST:
            response = requests.get(f"{url}/purchase_upgrade?team_id={team.name}&category={request.POST['category']}&upgrade_id={request.POST['purchase']}")
    try:
        response = requests.get(f"{url}/get_upgrades?team_id={team.name}")
        data = json.loads(response.text)
    except Exception:
        data = []
    return render(request, "simulation/shop.html", {"products": data})

@login_required(redirect_field_name=None,login_url="login")
@user_passes_test(is_player,"home",redirect_field_name=None)
def messages_dashboard(request):
    check_teams()
    team = get_team_by_user(request.user)
    try:
        response = requests.get(f"{url}/get_messages?team_id={team.name}")
        messages = json.loads(response.text)
        #datetime.strptime(messages['messages'][0]['timestamp'].split(".")[0], '%Y-%m-%d %H:%M:%S')
        messages['messages'].reverse()

    except Exception as e:
        print(e)
    return render(request, "simulation/messages.html", {"emails":messages})

@login_required(redirect_field_name=None,login_url="login")
@user_passes_test(is_player,"home",redirect_field_name=None)
def get_cycle(request):
    check_teams()
    team = get_team_by_user(request.user)
    try:
        res = requests.get(f"{url}/get_factory_state?team_id={team.name}")
        data = json.loads(res.text)
        return JsonResponse(data)
    except Exception as e:
        print(e)
    return ""

@login_required(redirect_field_name=None,login_url="login")
@user_passes_test(is_admin)
def start_game(request):
    check_teams()
    teams = Team.objects.all()
    for t in teams:
        for u in t.members.all():
            u.is_active = True
            u.save()


        wazuh_pass = f"tempP@ssw0rd_{t.name}"
        body = f"""A Wazuh instance has been created for your team.You can access it at: <a href="https://localhost:{t.port}">https://localhost:{t.port}</a>.
        The username is: user. Use the following password: {wazuh_pass}"""
        headers = {'Content-Type': 'application/json'}
        res = os.popen("curl -X POST http://localhost:6000/deploy   -H 'Content-Type: application/json' -d '{\"port\":"+str(t.port)+", \"password\": \""+wazuh_pass+"\"}'").read()
        #res = requests.post(f"http://localhost:6000/deploy",data={"port":wazuh_port,"password":wazuh_pass},headers=headers)
        res = requests.get(f"{url}/send_message?team_id={t.name}&sender=Admin&subject=Wazuh Access&body={body}")
        wazuh_port+=100
    
    return redirect("admin_dashboard")

@login_required(redirect_field_name=None,login_url="login")
@user_passes_test(is_admin)
def end_game(request):
    None

@login_required(redirect_field_name=None,login_url="login")
@user_passes_test(is_admin)
def admin_dashboard(request):
    """Admin dashboard view (for non-Django admin)"""
    check_teams()
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
    try:
        res = requests.get(f"{url}/get_attacks")
        attacks = json.loads(res.text)
        attacks = attacks['attacks']
    except Exception as e:
        print(e)
    return render(request, "simulation/admin_dashboard.html", {"teams": teams, "players":users, "attacks":attacks})

@login_required(redirect_field_name=None,login_url="login")
@user_passes_test(is_admin)
def send_attack(request):
    check_teams()
    if request.method=="POST":
        id = request.POST['attack']
        target = request.POST['target']
        if target=="all":
            targets = [t.name for t in Team.objects.all()]
        else:
            targets = [target]
        for t in targets:
            try:
                res = requests.get(f"{url}/send_attack?team_id={t}&attack_index={id}")
            except Exception as e:
                print(e)
    return redirect("admin_dashboard")

@login_required(redirect_field_name=None,login_url="login")
@user_passes_test(is_admin)
def send_message(request):
    check_teams()
    if request.method == "POST":
        subject = request.POST['subject']
        body = request.POST['text']
        recipient = request.POST['recipient']
        if recipient == "all":
            recipients = [t.name for t in Team.objects.all()]
        else:
            recipients = [recipient]
        for r in recipients:
            response = requests.get(f"{url}/send_message?team_id={r}&sender=Admin&subject={subject}&body={body}")
    return redirect("admin_dashboard")

@login_required(redirect_field_name=None,login_url="login")
@user_passes_test(is_admin)
def create_team(request):
    global wazuh_port
    check_teams()
    """View for admin to create a team"""
    if request.method == "POST":
        # Process form data here (you'd use a form in a real app)
        name = request.POST.get("name")
        description = request.POST.get("description")
        try:
            response = requests.get(f"{url}/add_team?team_id={name}")
        except Exception as e:
            print(e)
        team = Team(name=name, description=description, created_by=request.user, port=wazuh_port)
        team.save()
        wazuh_port+=100

        messages.success(request, f"Team '{name}' created successfully!")
        return redirect("admin_dashboard")

    return render(request, "simulation/create_team.html")

@login_required(redirect_field_name=None,login_url="login")
@user_passes_test(is_admin)
def add_user(request):
    check_teams()
    teams = Team.objects.filter(created_by=request.user)
    if request.method == "POST":
        username = request.POST.get("username")
        firstname = request.POST.get("firstname")
        lastname = request.POST.get("lastname")
        password = request.POST.get("password")
        user = get_user_model().objects.create_user(username=username,
                                                    password=password,
                                                    first_name=firstname,
                                                    last_name=lastname,
                                                    is_active=False)
        team = request.POST.get("team")
        for t in teams:
            if t.name == team:
                t.members.add(user)
        return redirect("admin_dashboard")
    return render(request, "simulation/add_user.html",{"teams": teams})