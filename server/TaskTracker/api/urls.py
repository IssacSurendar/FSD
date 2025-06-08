from django.urls import path, include
from rest_framework import routers
from api import views

router = routers.DefaultRouter()

urlpatterns = [
    path('', include(router.urls)),
    path('login', views.LoginViewSet.as_view()),
    path('user', views.UserViewSet.as_view()),
    path('project', views.ProjectViewSet.as_view()),
    path('task', views.TaskViewSet.as_view()),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework'))
]