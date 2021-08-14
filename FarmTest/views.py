from django.shortcuts import render, redirect
from rest_framework.generics import GenericAPIView
from FarmTest.serializers import (
    RegisterSerializer, EmailVerificationSerializer, LoginSerializer, PasswordResetSerializer, SetNewPasswordSerializer
    )
from rest_framework import response, status, views
from FarmTest.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from FarmTest.utils import sendEmail
import jwt
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode


# Create your views here.
class RegisterAPIView(GenericAPIView):
    
    serializer_class = RegisterSerializer
    queryset = User.objects.all()

    def post(self, request):

        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            serializer.save()
            user_data = serializer.data

            user = User.objects.get(email=user_data['email'])
            token = RefreshToken.for_user(user).access_token

            current_site = get_current_site(request).domain
            relative_link = reverse('FarmTest:email-verification')
            absurl = 'http://'+current_site+relative_link+'?token='+str(token)
            email_body = 'Use this link to verify your email. \n'+absurl
            data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Verify your email'}

            sendEmail.send_email(data)

            return response.Response(serializer.data, status=status.HTTP_201_CREATED)
        return response.Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailAPIView(views.APIView):

    serializer_class = EmailVerificationSerializer

    def get(self, request):

        try:
            token = request.GET.get('token')
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])

            if not user.email_verified:

                user.email_verified = True
                user.save()

            return response.Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)

            return redirect('FarmTest:login')

        except jwt.ExpiredSignatureError as identifier:
            return response.Response({'error': 'Activation link expired. Request for a new one'}, status=status.HTTP_400_BAD_REQUEST)
        
        except jwt.exceptions.DecodeError as identifier:
            return response.Response({'error': 'Invalid token. Request for a new one'}, status=status.HTTP_400_BAD_REQUEST)



class LoginAPIView(GenericAPIView):

    queryset = User.objects.all()
    serializer_class = LoginSerializer

    def post(self, request):
        
        token = request.GET.get('token')
        resp = response.Response()
        resp.set_cookie(key='jwt', value=token, httponly=True)
        
        email = request.data.get('email', None)
        password = request.data.get('password', None)

        user = authenticate(username=email, password=password)

        if user:
            serializer = self.serializer_class(user)

            if not user.email_verified:
                return response.Response({'message':'Email not yet verified. Check your email for activation link'}, status=status.HTTP_401_UNAUTHORIZED)
            else:
                return response.Response(serializer.data, status=status.HTTP_200_OK)
        return response.Response({'message':'Invalid Credentials!! Try Again..'}, status=status.HTTP_401_UNAUTHORIZED)

class LogoutAPIView(views.APIView):
    def post(self, request):
        
        resp = response.Response()
        resp.delete_cookie('jwt')
        return response.Response({'message': 'Successfully logged out.'}, status=status.HTTP_200_OK)


class TokenRefreshAPIView(views.APIView):
    serializer_class = PasswordResetSerializer

    def post(self, request): 

        serializer = self.serializer_class(data=request.data)
        email = request.data['email']
        
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            token = RefreshToken.for_user(user).access_token

            current_site = get_current_site(request).domain
            relative_link = reverse('FarmTest:email-verification')
            absurl = 'http://'+current_site+relative_link+'?token='+str(token)
            email_body = 'Use this link to verify your email. \n'+absurl
            data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Verify your email'}

            sendEmail.send_email(data)

        return response.Response({'message': 'A new account activation link has been sent to your email'}, status=status.HTTP_200_OK)   


class PasswordResetAPIView(GenericAPIView):
    serializer_class = PasswordResetSerializer

    def post(self, request): 
        serializer = self.serializer_class(data=request.data)
        email = request.data['email']
        
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=request).domain
            relative_link = reverse('FarmTest:password-reset', kwargs={'uidb64':uidb64, 'token':token})
            absurl = 'http://'+current_site+relative_link
            email_body = f'Use the link below to reset your password. \n\nFor security purpose, you are required to fill two extra fields. uidb64 - {uidb64} and token - {token}\n\n'+absurl
            data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Reset your Password'}

            sendEmail.send_email(data)
        return response.Response({'message': 'A password reset link has been sent to your email'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPIView(GenericAPIView):

    def get(self, request, uidb64, token):

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return response.Response({'error': 'Invalid token. Request for a new one'}, status=status.HTTP_401_UNAUTHORIZED)

            return response.Response({'success':True, 'message':'Credentials Valid', 'uidb64':uidb64, 'token':token}, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            return response.Response({'error': 'Invalid token. Request for a new one'}, status=status.HTTP_400_BAD_REQUEST)

class SetNewPasswordAPIView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return response.Response({'sucess':True, 'message':'Password reset done'}, status=status.HTTP_200_OK)