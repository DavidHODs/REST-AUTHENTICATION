from rest_framework import serializers
from FarmTest.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework.exceptions import AuthenticationFailed


class RegisterSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('email', 'password', 'password2', 'token')
        extra_kwargs = {
            'password':{'write_only':True},
            'password2':{'write_only':True}
        }

        read_only_fields = ['token']


    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        return attrs


    def create(self, validated_data):
        password2 = validated_data.pop('password2', None)
        return User.objects._create_user(**validated_data)


class EmailVerificationSerializer(serializers.ModelSerializer):

	token = serializers.CharField(max_length=1000)

	class Meta:
		model = User
		fields = ('token')


class LoginSerializer(serializers.ModelSerializer):
    
    password = serializers.CharField(max_length=128, min_length=8, write_only=True)

    class Meta:
        model = User
        fields = ('email', 'password', 'token')

        read_only_fields = ['token']

class PasswordResetSerializer(serializers.Serializer):

    email = serializers.EmailField(required=True)

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(required=True, write_only=True, min_length=8)
    token = serializers.CharField(write_only=True)
    uidb64 = serializers.CharField(write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid. Request for a new one.', 401)

            user.set_password(password)
            user.save()
            
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid. Request for a new one.', 401)
        return super().validate(attrs)
