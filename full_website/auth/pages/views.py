from turtle import update
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView

from pages.models import User

from pages.serializers import SendPasswordResetEmailSerializer, UserChangePasswordSerializer, UserLoginSerializer, UserPasswordResetSerializer, UserRegistrationSerializer, UserProfileSerializer
from django.contrib.auth import authenticate

from pages.renderers import UserRenderer

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
# Create your views here.


# patients start
from rest_framework.views import APIView

from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
import jwt
import datetime
# Create your views here.

# after onward login and register

import json
from django.http import JsonResponse
from django.shortcuts import render
import io
from rest_framework.parsers import JSONParser
from yaml import serialize
from .models import Patient
from .serializers import PatientSerializer, UserSerializer
from rest_framework.renderers import JSONRenderer
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View
from rest_framework.decorators import api_view
from bson.json_util import loads, dumps
import pymongo
from bson.json_util import dumps, loads
# end
from bson.objectid import ObjectId


# from rest_framework.authentication import TokenAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.decorators import authentication_classes

from django.http import JsonResponse
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView


# token generate
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        "access": str(refresh.access_token)
    }


class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = get_tokens_for_user(user)
        return Response({"token": token, "msg": "registered"}, status=status.HTTP_202_ACCEPTED)


class UserLoginView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get("email")
        password = serializer.data.get("password")
        user = authenticate(email=email, password=password)
        if user is not None:
            info = User.objects.filter(email=email).values_list("id", "name")
            id, name = info[0][0], info[0][1]
            data = {"id": id, "name": name}
            token = get_tokens_for_user(user)
            return Response({"token": token, "data": data}, status=status.HTTP_200_OK)
        else:
            return Response({"errors": {'non_field_errors': ["email or password is not valid"]}}, status=status.HTTP_404_NOT_FOUND)


class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_302_FOUND)


class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    # permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(
            data=request.data, context={"user": request.user})
        serializer.is_valid(raise_exception=True)
        return Response({"msg": "updated"}, status=status.HTTP_202_ACCEPTED)


class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"msg": "password rest link sent please check your email"}, status=status.HTTP_202_ACCEPTED)


class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(
            data=request.data, context={"uid": uid, "token": token})
        serializer.is_valid(raise_exception=True)
        return Response({"msg": "password rest successfully"}, status=status.HTTP_202_ACCEPTED)

# patients info


class PatientApi(APIView):
    renderer_classes = [UserRenderer]
    # permission_classes = [IsAuthenticated]
    def get(self, request, *args, **kwargs):
        data = Patient.objects.all()
        info = PatientSerializer(data, many=True)
        return Response(info.data, status=status.HTTP_202_ACCEPTED)

    def post(self, request, *args, **kwargs):
        # pythondata= JSONParser.parse(request)
        id = request.data["id"]
        doc_data = User.objects.get(id=id)
        doc_info = UserSerializer(doc_data)
        polit = doc_info.data.get("polit", None)
        if request.data["data"]["polit"].lower() == polit.lower():
            serializer = PatientSerializer(data=request.data["data"])
            if serializer.is_valid():
                serializer.save()
                return Response({"msg": "added the patient"})
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"msg": "polit vary! you can't add"},status=status.HTTP_406_NOT_ACCEPTABLE)

    def put(self, request, *args, **kwargs):
        id = request.data["id"]
        data = Patient.objects.get(id=id)
        info = PatientSerializer(data, data=request.data)
        info.is_valid(raise_exception=True)
        info.save()
        return Response({"msg": f'data updated of id: {id}'})

    def delete(self, request, *args, **kwargs):
        id = request.data["id"]
        data = Patient.objects.get(id=id)
        data.delete()
        return Response({"msg": f'{id} deleted from database'})


@api_view(['PATCH'])
# @permission_classes([IsAuthenticated])
def associate(request):
    update_data = dict()
    data = request.data["data"]
    remarks = request.data["remarks"]
    id = request.data["id"]
    update_data['data'] = data
    update_data['remarks'] = remarks
    update_data['id'] = id
    data = Patient.objects.get(id=id)
    info = PatientSerializer(data)
    old_data = info.data["data"]
    update_data["data"] = str(old_data) +" "+str(update_data["data"])
    # print(update_data["data"])
    serializer = PatientSerializer(data, data=update_data, partial=True)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response({"msg": f'id no: {id} data is updated'})

    # data = request.data["data"]
    # remarks = request.data["remarks"]
    # client = pymongo.MongoClient()
    # db = client['pratice']
    # collection_name = db["pages_data"]
    # id = request.data["_id"]
    # objInstance = ObjectId(id)
    # one_data = collection_name.find_one(objInstance)
    # previous_data = one_data["data"]
    # filter = {"_id": objInstance}
    # update = {"$set": {"data": previous_data+data, "remarks": remarks}}
    # # collection_name.update_one(filter, update)
    # collection_name.update(filter, update, upsert=True)
    # return JsonResponse({"msg": f'data associate with id no: {id}'})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def listOfRecordings(request):
    # renderer_classes=[UserRenderer]
    # client = pymongo.MongoClient(
    #     'mongodb+srv://Amjid:12341234@cluster0.rwsqgwf.mongodb.net/test')
    id = request.data["id"]
    data = User.objects.get(id=id)
    data = UserSerializer(data)
    polit = data.data["sensor"]
    if not polit or polit==None or polit==str(None):
        return Response({"msg": "poilat is not assigned yet contact to Admin"})
    else:
        client = pymongo.MongoClient()
        db = client['belt_Sensor']
        collection_name = db["student"]
        data = collection_name.find()
        list_data = clean(data, polit)
        filter_list = []
        for x in list_data:
            if x["info"]["sensor"].lower() == polit or x["info"]["sensor"] == polit[:2].lower():
                filter_list.append(x)
        def parse_json(data):
            return json.loads(dumps(data))
        if len(list_data) <= 1 or len(list_data) == 0:
            return Response({"msg": "no data"})
        else:
            out = parse_json(list_data)
            return JsonResponse(out, safe=False)


def clean(data, polit):
    list_data = []
    df = data
    for v, x in enumerate(df):
        if polit[:2].lower() in x["value"].replace(
                "\n", "").replace("\r", "").split(",")[0].lower() or polit.lower() in x["value"].replace(
                "\n", "").replace("\r", "").split(",")[0].lower():
            if v < 50:
                dict_data = dict()
                dict_data["info"] = dict()
                dict_data["id"] = x["_id"]
                dict_data["info"]["sensor"] = x["value"].replace(
                    "\n", "").replace("\r", "").split(",")[0]
                dict_data["info"]["person"] = x["value"].replace(
                    "\n", "").replace("\r", "").split(",")[1]
                dict_data["info"]["dont_know"] = x["value"].replace(
                    "\n", "").replace("\r", "").split(",")[2]
                dict_data["info"]["time_stamp"] = x["value"].replace(
                    "\n", "").replace("\r", "").split(",")[3]
                dict_data["info"]["data"] = x["value"].replace(
                    "\n", "").replace("\r", "").split(",")[4:]
                list_data.append(dict_data)
            else:
                break
        else:
            continue
    return list_data

    #     if v < 1:
    #         dict_data = dict()
    #         dict_data["info"] = dict()
    #         dict_data["id"] = x["_id"]
    #         dict_data["info"]["sensor"] = x["value"].replace(
    #             "\n", "").replace("\r", "").split(",")[0]
    #         dict_data["info"]["person"] = x["value"].replace(
    #             "\n", "").replace("\r", "").split(",")[1]
    #         dict_data["info"]["dont_know"] = x["value"].replace(
    #             "\n", "").replace("\r", "").split(",")[2]
    #         dict_data["info"]["time_stamp"] = x["value"].replace(
    #             "\n", "").replace("\r", "").split(",")[3]
    #         dict_data["info"]["data"] = x["value"].replace(
    #             "\n", "").replace("\r", "").split(",")[4:]
    #         list_data.append(dict_data)
    #     else:
    #         break
    # return list_data


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cleaning_data(request):
    string = []
    return_data = dict()
    information = request.data
    recording = information["recordings"]
    for x in recording:
        data = ",".join(map(str, x[0]["info"]["data"]))
        string.append(data)
    return_data["data"] = ",".join(string)
    return_data["id"] = information["patentId"]
    return Response(return_data)
