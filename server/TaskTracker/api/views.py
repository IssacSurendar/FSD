from django.contrib.auth.models import Group, User
from rest_framework import permissions, viewsets
from api.models import Project, Task, UserMeta
from api.serializers import UserSerializer, ProjectSerializer, TaskSerializer, TokenSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import jwt, time
from datetime import datetime, timedelta
from django.http import JsonResponse
from rest_framework.exceptions import ValidationError
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone

SECRET_NAME = "FSDTT@2025"



class LoginViewSet(APIView):
 
    def post(self, request, format=None):
        serializer = TokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.data
        if user.get('email') and user.get('password') and user.get('sso') == False:

            current_user = User.objects.filter(email=user.get('email')).first()
            passwordCheck = check_password(user.get('password'), current_user.password) 
            # print(passwordCheck)
            if current_user and passwordCheck:
                user_meta = UserMeta.objects.filter(user=current_user.id).first()
                if user_meta:
                    payload = request.data
                    payload.pop('password')
                    payload['id'] = current_user.id
                    payload['user_meta_id'] = user_meta.id
                    payload['username'] = current_user.username
                    payload['iat']= int(time.time())
                    payload['exp']= int(time.time() + 3 * 60 * 60)
                    payload['picture'] = user_meta.picture
                    payload['role'] = user_meta.role
            else:
                return Response({'message': 'Invalid credentials', 'result': {}}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            current_user = UserMeta.objects.filter(user__email=user.get('email')).first()
            if current_user:
                # print(current_user.user.username)
                user_meta = UserMeta.objects.select_related('user').filter(user=current_user.id).update(picture=user['picture'])
                payload = request.data
                payload['id'] = current_user.user.id
                payload['user_meta_id'] = current_user.id
                payload['username'] = current_user.user.username
                payload['iat']= int(time.time())
                payload['exp']= int(time.time() + 300 * 60 * 60)
                payload['picture'] = user['picture']
                payload['role'] = current_user.role
            else:
                return Response({'message': 'Insufficient access rights', 'result': {}}, status=status.HTTP_401_UNAUTHORIZED)
        
        token = jwt.encode(payload, SECRET_NAME, algorithm="HS256")
        return Response({'message': 'Loggedin successfully', 'result': {'token':token}}, status=status.HTTP_200_OK)



def headerValidation(header, page=''):
    response = {'message': 'Unauthorized', 'result': {}}
    decode_data = {}
    if 'Authorization' in header.keys():
        try:       
            token = header['Authorization']
            decode_data = jwt.decode(token, SECRET_NAME, algorithms=['HS256'])
        except Exception as Err:
            print(Err)
            return 401, response
    elif 'Authorization' not in header.keys():
        return 401, response
    if page == 'task' and str(decode_data.get('role')).lower() not in ['admin', 'taskcreator']:
        return 401, response
    return 200, decode_data




class UserViewSet(APIView):

    def get(self, request, format=None):
        
        status_code, jwt_response = headerValidation(request.headers)
        if status_code == 401:
            return JsonResponse(jwt_response, status=status_code)

        response = {'message': 'No data found', 'result': {}}
        status_code = status.HTTP_404_NOT_FOUND

        try:

            if jwt_response.get('role') in ['Admin', 'TaskCreator']:
                role_id = request.GET.get('role') 
                if role_id is None:
                    user = UserMeta.objects.select_related('user').values('user__username', 'user__email', 'role','picture', 'id', 'user__id', 'created_at', 'updated_at').order_by('-updated_at')
                else:
                    user = UserMeta.objects.select_related('user').filter(role=role_id).values('user__username', 'user__email', 'role','picture', 'id', 'user__id', 'created_at', 'updated_at')
                if len(user) != 0:
                    message = f"{len(user)} users found"
                    status_code = status.HTTP_200_OK
                else:
                    message = 'User not found'
                response['result'] = list(user)
            else:
                message = 'Insufficent permission'
                status_code = 403

            response['message'] = message
            return JsonResponse(response, status=status_code, safe=False)
            
        except Exception as Err:
            response['result']['error'] = str(Err)
        return Response(response, status=status_code)


    def post(self, request, format=None):

        status_code, response = headerValidation(request.headers)
        if status_code == 401:
            return JsonResponse(response, status=status_code)

        if response.get('role') == 'Admin':
            serializer = TokenSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            user = request.data

            user_info, created = User.objects.get_or_create(
                email = user['email'],
                defaults={
                    'email':user['email'], 
                    'username':user['username'], 
                    'password': make_password("test@123")
                }
            )
            
            if created:
                user_info.save()
                user_meta = UserMeta.objects.create(user=user_info, role=user.get('role', 'User'))
                user_meta.save()
                message = 'User created successfully'
                status_code = status.HTTP_201_CREATED
            else:
                message = 'User already exist'
                status_code = status.HTTP_400_BAD_REQUEST
        else:
            message = 'Insufficent permission'
            status_code = 403

        return Response({'message': message, 'result': {}}, status=status_code)


    def delete(self, request, format=None):

        status_code, response = headerValidation(request.headers)
        if status_code == 401:
            return JsonResponse(response, status=status_code)

        if response.get('role') == 'Admin':
            payload = request.data
            try:
                deleted = User.objects.filter(
                    id = payload.get('id')
                ).delete()
                print('user', deleted)
                user_deleted = UserMeta.objects.filter(
                    user = payload.get('id')
                ).delete()
                print('user meta', user_deleted)
          
                message = 'User deleted successfully'
                status_code = status.HTTP_200_OK
            except Exception as Err:
                print(Err)
                message = 'Bad request data'
                status_code = 400
        else:
            message = 'Insufficient permission'
            status_code = 403

        return Response({'message': message, 'result': {}}, status=status_code)


    def put(self, request, format=None):

        status_code, response = headerValidation(request.headers)
        if status_code == 401:
            return JsonResponse(response, status=status_code)

        if response.get('role') == 'Admin':
            payload = dict(request.data)

            status_code = 400
            response = {'message': 'Invalid request data', 'result': {}}
            if 'id' not in list(payload.keys()):
                return JsonResponse(response, status=422)

            filter = {'id':payload.get('id')}
            role = {'role': payload.pop('role')}
            user_update = User.objects.filter(**filter).update(**payload)
            filter = {'user__id':payload.get('id')}
            user_meta_update = UserMeta.objects.filter(**filter).update(**role)

            if user_update and user_meta_update:
                response['message'] = 'User updated successfully'
                status_code = 200
        else:
            response['message'] = "Insufficient permissions"
            status_code = 403
  
        return JsonResponse(response, status=status_code)





class ProjectViewSet(APIView):

    def get(self, request, format=None):
        
        status_code, jwt_response = headerValidation(request.headers)
        if status_code == 401:
            return JsonResponse(jwt_response, status=status_code)
        
        status_code = status.HTTP_404_NOT_FOUND
        response = {'message': 'No data found', 'result': {}}
        try:
            if jwt_response.get('role') in ['Admin', 'TaskCreator']:
                project_id = request.GET.get('id') 
                if project_id:
                    project = Project.objects.select_related('created_by').select_related('created_by__user').filter(id=project_id).values('id','name', 'description', 'status', 'created_at', 'updated_at', 'created_by__user__username', 'created_by__user__email', 'created_by__picture', 'created_by__id')
                else:
                    project = Project.objects.select_related('created_by').select_related('created_by__user').values('id','name', 'description', 'status', 'created_at', 'updated_at', 'created_by__user__username', 'created_by__user__email', 'created_by__picture').order_by('-updated_at')
                if len(project) != 0:
                    message = f"{len(project)} projects found"
                    status_code = status.HTTP_200_OK
                response['message'] = message
                response['result'] = list(project)
            else:
                response['message'] = 'Insufficent permission'
                status_code = 403
            return JsonResponse(response, status=status_code, safe=False)
            
        except Exception as Err:
            response['result']['error'] = str(Err)
        return Response(response, status=status_code)


    def post(self, request, format=None):

        status_code, response = headerValidation(request.headers)
        if status_code == 401:
            return JsonResponse(response, status=status_code)
        if response.get('role') == 'Admin':
            data = request.data
            serializer = ProjectSerializer(data=data)
            serializer.is_valid(raise_exception=True)
    
            user = UserMeta.objects.get(id=response.get('user_meta_id'))
    
            project_info, created = Project.objects.get_or_create(
                name = data.get('name'),
                defaults={
                    'name':data.get('name'), 
                    'description':data.get('description', ''), 
                    'status': data.get('status'),
                    'created_by' : user
                }
            )
            if created:
                project_info.save()
                message = 'Project created successfully'
                status_code = status.HTTP_201_CREATED
            else:
                message = 'Project name already exist'
                status_code = status.HTTP_400_BAD_REQUEST
        else:
            message = 'Insufficent permission'
            status_code = 403

        return Response({'message': message, 'result': {}}, status=status_code)


    def put(self, request, format=None):

        status_code, response = headerValidation(request.headers)
        if status_code == 401:
            return JsonResponse(response, status=status_code)

        if response.get('role') == 'Admin':
            payload = request.data

            status_code = 400
            response = {'message': 'Invalid request data', 'result': {}}
            if 'id' not in list(payload.keys()):
                return JsonResponse(response, status=422)
            filter = {'id':payload.get('id')}
            payload['updated_at'] = datetime.now()
            task_update = Project.objects.filter(**filter).update(**payload)

            if task_update:
                response['message'] = 'Project updated successfully'
                status_code = 200
        else:
            response['message'] = "Insufficient permissions"
            status_code = 403
  
        return JsonResponse(response, status=status_code)


    def delete(self, request, format=None):

        status_code, response = headerValidation(request.headers)
        if status_code == 401:
            return JsonResponse(response, status=status_code)

        if response.get('role') == 'Admin':
            payload = request.data
            try:
                deleted = Project.objects.get(
                    id = payload.get('id')
                ).delete()
            except Exception as Err:
                deleted = None
            
            if deleted:
                message = 'Task deleted successfully'
                status_code = status.HTTP_200_OK
            else:
                message = f"No data found."
                status_code = status.HTTP_400_BAD_REQUEST
        else:
            message = 'Insufficient permission'
            status_code = 403

        return Response({'message': message, 'result': {}}, status=status_code)



class TaskViewSet(APIView):


    def get(self, request, format=None):
        
        status_code, jwt_response = headerValidation(request.headers)
        if status_code == 401:
            return JsonResponse(jwt_response, status=status_code)
        
        status_code = 200
        response = {'message': 'No data found', 'result': {}}
        try:
            task_id = request.GET.get('id') 
            if task_id:
                task = Task.objects.select_related('owner').select_related('owner__user').select_related('assigned_to').select_related('assigned_to__user').select_related('project').filter({'id':task_id}).values('id', 'title','description','status', 'due_date', 'owner__user__username','owner__user__email','owner__id','owner__user__id','owner__picture','assigned_to__user__username','assigned_to__user__email','assigned_to__id','assigned_to__user__id', 'assigned_to__picture','project__id', 'project__name', 'project__description')
            else:
                filter = {}
                if jwt_response.get('role') == 'TaskCreator':
                    filter['owner'] = jwt_response.get('user_meta_id')
                elif jwt_response.get('role') == 'User':
                    filter['assigned_to'] = jwt_response.get('user_meta_id')
   
                task = Task.objects.select_related('owner').select_related('owner__user').select_related('assigned_to').select_related('assigned_to__user').select_related('project').filter(**filter).values('id','title','description','status', 'due_date', 'owner__user__username','owner__user__email','owner__id','owner__user__id','owner__picture','assigned_to__user__username','assigned_to__user__email','assigned_to__id','assigned_to__user__id', 'assigned_to__picture','project__id', 'project__name', 'project__description').order_by('-updated_at')

            if len(task) != 0:
                response['message'] = f"{len(task)} tasks found"
    

            response['result'] = list(task)
            return JsonResponse(response, status=status_code, safe=False)
            
        except Exception as Err:
            response['result']['error'] = str(Err)
        return Response(response, status=status_code)


    def post(self, request, format=None):

        status_code, response = headerValidation(request.headers, 'task')
        if status_code == 401:
            return JsonResponse(response, status=status_code)

        data = request.data
        serializer = TaskSerializer(data=data)
        serializer.is_valid(raise_exception=True)
 
        data['owner'] = UserMeta.objects.get(id=int(data.get('owner')))
        data['assigned_to'] = UserMeta.objects.get(id=int(data.get('assigned_to')))
        data['project'] = Project.objects.get(id=int(data.get('project')))
        # print(data)
        try:
            project_info, created = Task.objects.get_or_create(
                title = data.get('title'),
                defaults= data
            )
        except Exception as Err:
            print(Err)
        if created:
            project_info.save()
            message = 'task created successfully'
            status_code = status.HTTP_201_CREATED
        else:
            message = 'task name already exist'
            status_code = status.HTTP_400_BAD_REQUEST

        return Response({'message': message, 'result': {}}, status=status_code)


    def put(self, request, format=None):

        status_code, response = headerValidation(request.headers)
        if status_code == 401:
            return JsonResponse(response, status=status_code)

        payload = request.data

        filter = {'id': payload.get('id')}
        if 'TaskCreator' == response.get('role'):
            filter['owner'] = response.get('user_meta_id')

        status_code = 400
        response = {'message': 'Invalid request data', 'result': {}}
        if 'id' not in list(payload.keys()):
            return JsonResponse(response, status=422)
        
        # payload['updated_at'] = datetim       e.now()
        # due_date = datetime.strptime(payload['due_date'] + ":01.001", "%Y-%m-%dT%H:%M:%S.%f")
        # aware_dt = timezone.make_aware(due_date)
        # payload['due_date'] = due_date
        # payload.pop('due_date')
        print(payload)
        print(filter)
        task_update = Task.objects.filter(**filter).update(**payload)
        print(task_update)
        if task_update:
            response['message'] = 'Task updated successfully'
            status_code = 200
        else:
            response['message'] = "Insufficient permissions"
            status_code = 403
  
        return JsonResponse(response, status=status_code)

    
    def delete(self, request, format=None):

        status_code, response = headerValidation(request.headers, 'task')
        if status_code == 401:
            return JsonResponse(response, status=status_code)

        payload = dict(request.data)

        try:
            filter = {'id': payload.get('id')}
            if 'TaskCreator' == response.get('role'):
                filter['owner'] = response.get('user_meta_id')
            deleted = Task.objects.filter(**filter).delete()
        except Exception as Err:
            deleted = None
        
        if deleted[0] != 0:
            message = 'Task deleted successfully'
            status_code = status.HTTP_200_OK
        else:
            message = "Insufficient permissions"
            status_code = 403

        return Response({'message': message, 'result': {}}, status=status_code)


