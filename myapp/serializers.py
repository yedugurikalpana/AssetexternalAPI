from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import check_password
 
User = get_user_model()
 
class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'password', 'email')
        extra_kwargs = {'password': {'write_only': True}}
 
    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password'],
            email=validated_data['email']
        )
        return user
 
class VerifySerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()
    one_time_token = serializers.CharField()
 
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

class LoginVerifySerializer(serializers.Serializer):
    username = serializers.CharField()
    verification_code = serializers.CharField(max_length=6)

from rest_framework import serializers

class FlightByDateSerializer(serializers.Serializer):
    date = serializers.DateField()
    refresh_token = serializers.CharField(required=True)
    
class FlightByPlaceSerializer(serializers.Serializer):
     place = serializers.CharField()
refresh_token = serializers.CharField(required=True)

class FlightByPlaceResponseSerializer(serializers.Serializer):
    place = serializers.CharField()
    #date = serializers.DateField()
    incoming_flights_count = serializers.IntegerField()
    outgoing_flights_count = serializers.IntegerField()
    total_flights = serializers.IntegerField()
    

# Serializer for incoming request data with place and date
class FlightByPlaceAndDateSerializer(serializers.Serializer):
    place = serializers.CharField()
    date = serializers.DateField()
    refresh_token = serializers.CharField(required=True)

class FlightByPlaceAndDateResponseSerializer(serializers.Serializer):
    place = serializers.CharField()
    date = serializers.DateField()
    incoming_flights_count = serializers.IntegerField()
    outgoing_flights_count = serializers.IntegerField()
    total_flights = serializers.IntegerField()

class FlightSummarySerializer(serializers.Serializer):
    #date = serializers.DateField()
    refresh_token = serializers.CharField(required=True)