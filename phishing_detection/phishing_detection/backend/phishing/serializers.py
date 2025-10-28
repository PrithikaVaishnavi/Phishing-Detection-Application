from rest_framework import serializers
from django.contrib.auth.models import User
from django.db import IntegrityError
from .models import UserProfile
from email_validator import validate_email, EmailNotValidError

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)
    phone_number = serializers.CharField(required=False, allow_blank=True)
    email = serializers.CharField()  # Override default email validation

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password2', 'phone_number']

    def validate(self, data):
        # Validate password match
        if data['password'] != data['password2']:
            raise serializers.ValidationError({"password": "Passwords do not match"})

        # Custom email validation
        email = data.get('email')
        try:
            validate_email(email, check_deliverability=False)
        except EmailNotValidError as e:
            raise serializers.ValidationError({"email": str(e)})

        return data

    def create(self, validated_data):
        phone_number = validated_data.pop('phone_number', None)
        try:
            user = User.objects.create_user(
                username=validated_data['username'],
                email=validated_data['email'],
                password=validated_data['password']
            )
            UserProfile.objects.create(
                user=user,
                phone_number=phone_number if phone_number else ''
            )
            return user
        except IntegrityError as e:
            if 'username' in str(e).lower():
                raise serializers.ValidationError({"username": "This username is already taken."})
            elif 'email' in str(e).lower():
                raise serializers.ValidationError({"email": "This email is already in use."})
            raise serializers.ValidationError({"non_field_errors": "Registration failed due to a database error."})