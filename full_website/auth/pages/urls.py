from django.urls import path, include
from pages.views import UserRegistrationView, UserLoginView, UserProfileView, UserChangePasswordView, SendPasswordResetEmailView, UserPasswordResetView, PatientApi, associate, listOfRecordings, cleaning_data
urlpatterns = [
    # register and login
    path("register/", UserRegistrationView.as_view(), name="register"),
    path("login/", UserLoginView.as_view(), name="login"),
    path("profile/", UserProfileView.as_view(), name="profile"),
    path("changepassword/", UserChangePasswordView.as_view(), name="changepassword"),
    path("reset-password/<uid>/<token>/",
         UserPasswordResetView.as_view(), name="rest-password"),
    path("restpassword/", SendPasswordResetEmailView.as_view(),
         name="restpassword"),
    # register and login complete
    # add patients edit patients and more
    path("patient/", PatientApi.as_view()),
    path("associate/", associate),
    path("listOfRecordings/", listOfRecordings),
    path("cleandata/", cleaning_data),
]
