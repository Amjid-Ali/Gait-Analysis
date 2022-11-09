
from jsonschema import ValidationError
from rest_framework import serializers
from yaml import serialize
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from pages.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from pages.utils import Util


# patients
from rest_framework import serializers
from rest_framework import serializers
from .models import Patient


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["sensor", "polit"]


class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(
        style={"input_type": "password"}, write_only=True)

    class Meta:
        model = User
        fields = ["email", "name", "country_name", "hospital_name", "password",
                  "password2", ]
        extra_kwargs = {
            'password': {"write_only": True}
        }

    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.get("password2")
        if password != password2:
            raise serializers.ValidationError(
                "password and confirm password doesn't match")
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = User
        fields = ["email", "password"]
        # fields = '__all__'


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'name']


class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=255, style={"input_type": "password"}, write_only=True)
    password2 = serializers.CharField(
        max_length=255, style={"input_type": "password"}, write_only=True)

    class Meta:
        fields = ["password", "password2"]

    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.get("password2")
        user = self.context.get("user")
        if password != password2:
            raise serializers.ValidationError(
                "password and confirm password doesn't match")
        user.set_password(password)
        user.save()
        return attrs


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ["email"]

    def validate(self, attrs):
        email = attrs.get("email")
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            print("user", user)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print("bytes uid", uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print("token", token)
            link = 'http://localhost:3000/api/reset-password/'+uid+"/"+token
            print("link", link)
            # send email
            body = "Click Following Link to Reset Your Password "+link
            data = {
                'subject': 'Rest Your Password',
                'body': body,
                # 'body': f' Click the Follow Link to Reset Your Passsword {link}',
                'to_email': user.email
            }
            Util.send_email(data)
            return attrs
        else:
            raise ValidationError("you are not registered user")


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=255, style={"input_type": "password"}, write_only=True)
    password2 = serializers.CharField(
        max_length=255, style={"input_type": "password"}, write_only=True)

    class Meta:
        fields = ["password", "password2"]

    def validate(self, attrs):
        try:
            password = attrs.get("password")
            password2 = attrs.get("password2")
            uid = self.context.get("uid")
            token = self.context.get("token")
            if password != password2:
                raise serializers.ValidationError(
                    "password and confirm password doesn't match")
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise ValidationError("Token is not valid or Expired")
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise ValidationError("Token is not valid or Expired")


class PatientSerializer(serializers.ModelSerializer):
    class Meta:
        model = Patient
        fields = ["id", "name", "dob", "address",
                  "comments", "data", "remarks", "annotation", ]
