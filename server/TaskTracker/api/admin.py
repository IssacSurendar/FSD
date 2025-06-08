from django.contrib import admin
from api.models import Task, Project, UserMeta

# Register your models here.
admin.site.register(Project)
admin.site.register(Task)
admin.site.register(UserMeta)
