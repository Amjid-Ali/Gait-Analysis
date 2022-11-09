
from email.policy import default
from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser


from djongo import models
from sqlalchemy import null
from sympy import polar_lift

# patients models


class Patient(models.Model):
    name = models.CharField(max_length=100)
    dob = models.DateField()
    address = models.CharField(max_length=100)
    comments = models.CharField(max_length=100, blank=True, default="")
    data = models.TextField(blank=True, default="")
    remarks = models.CharField(max_length=255, blank=True, default="")
    annotation = models.CharField(max_length=255, blank=True, default="")
    polit = models.CharField(max_length=255, blank=True)


class UserManager(BaseUserManager):
    def create_user(self, email, name, country_name, hospital_name, polit, password=None, password2=None):
        """
        Creates and saves a User with the given email, date of
        birth and password.
        """
        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(
            email=self.normalize_email(email),
            name=name,
            country_name=country_name,
            hospital_name=hospital_name,
            polit=polit
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, country_name, hospital_name, polit, password=None, ** kwargs):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        user = self.create_user(
            email,
            password=password,
            name=name,
            country_name=country_name,
            hospital_name=hospital_name,
            polit=polit
        )
        user.is_admin = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    email = models.EmailField(
        verbose_name='email',
        max_length=255,
        unique=True,
    )
    name = models.CharField(max_length=255)
    hospital_name = models.CharField(
        max_length=255, default="", blank=True)
    country_name = models.CharField(
        max_length=255, default="", blank=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    polit = models.CharField(max_length=255)
    sensor = models.CharField(max_length=255, blank=True, default="")

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', "polit", "hospital_name", "country_name"]

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        # return True
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        # return True
        return self.is_admin

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin
