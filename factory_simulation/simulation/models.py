from django.db import models
from django.contrib.auth.models import User


class Team(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Admin user who created the team
    created_by = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="created_teams"
    )

    # Team members (each team needs at least one user)
    members = models.ManyToManyField(
        User, through="TeamMembership", related_name="teams"
    )

    def __str__(self):
        return self.name


class TeamMembership(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    team = models.ForeignKey(Team, on_delete=models.CASCADE)
    date_joined = models.DateTimeField(auto_now_add=True)

    ROLE_CHOICES = [
        ("MEMBER", "Team Member"),
        ("LEADER", "Team Leader"),
    ]
    role = models.CharField(
        max_length=10,
        choices=ROLE_CHOICES,
        default="MEMBER",
    )

    class Meta:
        unique_together = ("user", "team")

    def __str__(self):
        return f"{self.user.username} - {self.team.name} ({self.get_role_display()})"


# You can add more models for the factory simulation as needed
class Product(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)

    def __str__(self):
        return self.name

