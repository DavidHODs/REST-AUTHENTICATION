from django.urls import path, include
from FarmTest.views import (
    RegisterAPIView, VerifyEmailAPIView, LoginAPIView, LogoutAPIView, PasswordTokenCheckAPIView, PasswordResetAPIView, SetNewPasswordAPIView, TokenRefreshAPIView
    )


app_name = 'FarmTest'

urlpatterns = [
    path('signup', RegisterAPIView.as_view(), name='signup'),
    path('email-verification', VerifyEmailAPIView.as_view(), name='email-verification'),
    path('login', LoginAPIView.as_view(), name='login'),
    path('logout', LogoutAPIView.as_view(), name='logout'),
    path('password-reset-complete', SetNewPasswordAPIView.as_view(), name='reset-email-complete'),
    path('password-reset-email', PasswordResetAPIView.as_view(), name='password-reset-email'),
    path('password-reset/<uidb64>/<token>', PasswordTokenCheckAPIView.as_view(), name='password-reset'),
    path('token-refresh', TokenRefreshAPIView.as_view(), name='token-refresh'),
]