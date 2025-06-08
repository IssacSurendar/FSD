from django.db import models
from django.contrib.auth.models import User # new

PROJECT_STATUS = [
    ('Open', 'Open'),
    ('InProgress', 'In Progress'),
    ('Hold', 'Hold'),
    ('Completed', 'Completed'),
    ('Closed', 'Closed'),
]


ROLE = [
    ('Admin', 'Admin'),
    ('TaskCreator', 'Task Creator'),
    ('User', 'User')
]



class Token(models.Model):
    username = models.CharField(max_length=100, blank=True)
    email = models.EmailField()
    picture = models.URLField(default='', blank=True)
    reset = models.BooleanField(default=False)


class UserMeta(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_data')
    picture = models.URLField(default='', blank=True)
    role = models.CharField(max_length=20, choices=ROLE, default='User')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.user.username



# Create your models here.
class Project(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=255, choices=PROJECT_STATUS, default='Open')
    created_by = models.ForeignKey(UserMeta, on_delete=models.SET_NULL, null=True) 
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


TASK_STATUS_CHOICES = [
    ('Pending', 'Pending'),
    ('InProgress', 'In Progress'),
    ('Hold', 'Hold'),
    ('Completed', 'Completed')
]


class Task(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    due_date = models.DateTimeField()
    status = models.CharField(max_length=20, choices=TASK_STATUS_CHOICES, default='Pending')
    owner = models.ForeignKey(UserMeta, on_delete=models.SET_NULL, null=True, related_name='owned_tasks')
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='tasks')
    assigned_to = models.ForeignKey(UserMeta, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_tasks')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title