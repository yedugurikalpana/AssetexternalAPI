from django.shortcuts import render

# Create your views here.
from django.shortcuts import render

# Create your views here.
from django.shortcuts import render

# Create your views here.
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.tokens import RefreshToken
import secrets
from .models import CustomUser, UserActivityLog
from .serializers import RegisterSerializer, VerifySerializer, LoginSerializer, LoginVerifySerializer
from .utils import log_user_activity

User = get_user_model()
Userdetails = UserActivityLog()

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            one_time_token = secrets.token_hex(16)
            user.one_time_token = one_time_token
            user.save()
            log_user_activity(user, 'POST', '/api/register/')
            return Response({'one_time_token': one_time_token}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyView(APIView):
    def post(self, request):
        serializer = VerifySerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            one_time_token = serializer.validated_data['one_time_token']
            try:
                user = User.objects.get(username=username)
                if user.one_time_token == one_time_token and check_password(password, user.password):
                    user.is_verified = True
                    user.one_time_token = None
                    user.save()
                    log_user_activity(user, 'POST', '/api/verify/')
                    return Response({'message': 'User verified'}, status=status.HTTP_200_OK)
                return Response({'message': 'Invalid credentials or token'}, status=status.HTTP_400_BAD_REQUEST)
            except User.DoesNotExist:
                return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            try:
                user = CustomUser.objects.get(username=username)
                if not user.check_password(password):
                    return Response({'message': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

                # Generate verification code
                user.generate_verification_code()
                log_user_activity(user, 'POST', '/api/login/')
                return Response({'verification_code': user.verification_code}, status=status.HTTP_200_OK)
            except CustomUser.DoesNotExist:
                return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginVerifyView(APIView):
    def post(self, request):
        serializer = LoginVerifySerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            verification_code = serializer.validated_data['verification_code']
            try:
                user = CustomUser.objects.get(username=username)
                if not user.is_verification_code_valid() or user.verification_code != verification_code:
                    return Response({'error': 'Invalid verification code or verification code expired!'}, status=status.HTTP_400_BAD_REQUEST)

                user.verification_code = None
                user.verification_code_created_at = None
                user.save()

                refresh = RefreshToken.for_user(user)
                log_user_activity(user, 'POST', '/api/login/verify/')
                Userdetails.user=CustomUser.objects.get(username=username)
                return Response({'refresh': str(refresh)}, status=status.HTTP_200_OK)
            except CustomUser.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from datetime import datetime
import requests
import json
import logging
from rest_framework_simplejwt.tokens import AccessToken, TokenError
from .serializers import FlightByDateSerializer,FlightByPlaceSerializer,FlightByPlaceAndDateSerializer,FlightByPlaceAndDateResponseSerializer,FlightByPlaceResponseSerializer,FlightSummarySerializer
from .models import FlightRequest, FlightSummary

logger = logging.getLogger(__name__)

def get_iata_code(place_name):
    # Define the IATA code mapping for cities
    place_to_iata = {
        'Mumbai': 'BOM',
        'Bengaluru': 'BLR',
        'Delhi': 'DEL',
        'Chennai': 'MAA',
        'Hyderabad': 'HYD',
        'Pune': 'PNQ',
        'Ahmedabad': 'AMD',
        'Goa': 'GOI',
        'Cochin': 'COK',
        'Kolkata': 'CCU',
        'Trivandrum':'TRV'

        # Add other mappings as needed
    }
    return place_to_iata.get(place_name)
def validate_refresh_token(token):
    try:
        # Decode the refresh token to validate
        token_obj = RefreshToken(token)
        return token_obj  # Return the token object if valid
    except TokenError:
        return None

# Function to fetch flight data from Amadeus API
def fetch_flight_data(endpoint, params, headers):
    try:
        response = requests.get(endpoint, headers=headers, params=params)
        response.raise_for_status()  # Raise HTTPError for bad responses
        return response.json()  # Return JSON response if successful
    except requests.RequestException as e:
        logger.error(f"Error fetching flight data: {e}")
        return None

# Function to get Amadeus access token
def get_amadeus_access_token():
    try:
        response = requests.post(
            'https://test.api.amadeus.com/v1/security/oauth2/token',
            data={
                'grant_type': 'client_credentials',
                'client_id': settings.AMADEUS_API_KEY,
                'client_secret': settings.AMADEUS_API_SECRET
            }
        )
        response.raise_for_status()
        return response.json().get('access_token')
    except requests.RequestException as e:
        logger.error(f"Error obtaining Amadeus access token: {e}")
        return None

@api_view(['POST'])
def flight_by_date_view(request):
    serializer = FlightByDateSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    date = serializer.validated_data['date']

    refresh_token = request.data.get('refresh_token')
    if not refresh_token or validate_refresh_token(refresh_token) is None:
        return Response({'error': 'Invalid or missing refresh token.'}, status=status.HTTP_401_UNAUTHORIZED)

    place_names = ['Mumbai', 'Bengaluru', 'Delhi', 'Chennai', 'Hyderabad']

    # Map place names to IATA codes
    iata_codes = [get_iata_code(name) for name in place_names]
    if None in iata_codes:
        return Response({'error': 'One or more place names could not be mapped to IATA codes.'}, status=status.HTTP_400_BAD_REQUEST)

    # Create and save FlightRequest record
    flight_request = FlightRequest.objects.create(
        request_type='by_date',
        date=date,
        iata_codes=iata_codes
    )

    headers = {'Authorization': f'Bearer {get_amadeus_access_token()}'}
    result = {}

    iata_to_place = {get_iata_code(name): name for name in place_names}

    for code in iata_codes:
        incoming_flights_count, outgoing_flights_count = 0, 0

        for destination_code in iata_codes:
            if destination_code != code:  # Skip the place itself
                outgoing_params = {
                    'originLocationCode': code,
                    'destinationLocationCode': destination_code,
                    'departureDate': date,
                    'adults': 1
                }
                incoming_params = {
                    'originLocationCode': destination_code,
                    'destinationLocationCode': code,
                    'departureDate': date,
                    'adults': 1
                }
            
                outgoing_data = fetch_flight_data(f"{settings.AMADEUS_BASE_URL}/v2/shopping/flight-offers", outgoing_params, headers)
                incoming_data = fetch_flight_data(f"{settings.AMADEUS_BASE_URL}/v2/shopping/flight-offers", incoming_params, headers)

                if outgoing_data:
                    outgoing_flights_count += len(outgoing_data.get('data', []))
                if incoming_data:
                    incoming_flights_count += len(incoming_data.get('data', []))
            
        place_name = iata_to_place.get(code, code)

        result[place_name] = {
            'date': date,
            'incoming_flights': incoming_flights_count,
            'outgoing_flights': outgoing_flights_count,
            'total_flights': incoming_flights_count + outgoing_flights_count
        }

        # Save flight summary
        FlightSummary.objects.create(
            flight_request=flight_request,
            place=place_name,  # Save the place name instead of the IATA code
            date=date,
            incoming_flights_count=incoming_flights_count,
            outgoing_flights_count=outgoing_flights_count,
            total_flights=incoming_flights_count + outgoing_flights_count
        )
    user = Userdetails.user
    log_user_activity(user, 'POST', '/api/flight/by-date/')
    return Response(result)




@api_view(['POST'])
def flight_by_place_view(request):
    serializer = FlightByPlaceSerializer(data=request.data)
    if serializer.is_valid():
        place = serializer.validated_data['place']
        date = request.data.get('date', datetime.now().strftime('%Y-%m-%d'))  # Default to current date if not provided
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    refresh_token = request.data.get('refresh_token')
    if not refresh_token or validate_refresh_token(refresh_token) is None:
        return Response({'error': 'Invalid or missing refresh token.'}, status=status.HTTP_401_UNAUTHORIZED)

    iata_code = get_iata_code(place)
    if not iata_code:
        return Response({'error': 'Place not found'}, status=status.HTTP_400_BAD_REQUEST)

    access_token = get_amadeus_access_token()
    if not access_token:
        return Response({'error': 'Failed to obtain Amadeus access token'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    headers = {'Authorization': f'Bearer {access_token}'}

    # Initialize counters
    incoming_flights_count = 0
    outgoing_flights_count = 0

    # Prepare destination IATA codes
    destinations = list(get_iata_code(place) for place in [
        'Mumbai', 'Bengaluru', 'Delhi', 'Chennai', 'Hyderabad', 'Pune', 'Ahmedabad', 'Goa', 'Cochin', 'Kolkata'
    ])
    destinations.remove(iata_code)  # Exclude the origin place

    for destination in destinations:
        outgoing_params = {
            'originLocationCode': iata_code,
            'destinationLocationCode': destination,
            'departureDate': date,
            'adults': 1
        }
        incoming_params = {
            'originLocationCode': destination,
            'destinationLocationCode': iata_code,
            'departureDate': date,
            'adults': 1
        }

        # Fetch outgoing flights
        outgoing_data = fetch_flight_data(f"{settings.AMADEUS_BASE_URL}/v2/shopping/flight-offers", outgoing_params, headers)
        # Fetch incoming flights
        incoming_data = fetch_flight_data(f"{settings.AMADEUS_BASE_URL}/v2/shopping/flight-offers", incoming_params, headers)

        # Update counts
        outgoing_flights_count += len(outgoing_data.get('data', [])) if outgoing_data else 0
        incoming_flights_count += len(incoming_data.get('data', [])) if incoming_data else 0

    result = {
        'place': place,
        'date': date,
        'incoming_flights_count': incoming_flights_count,
        'outgoing_flights_count': outgoing_flights_count,
        'total_flights': incoming_flights_count + outgoing_flights_count
    }

    response_serializer = FlightByPlaceResponseSerializer(result)
    
    user = Userdetails.user
    log_user_activity(user, 'POST', '/api/flight/by-place/')
    return Response(response_serializer.data)

@api_view(['POST'])
def flight_by_place_and_date_view(request):
    serializer = FlightByPlaceAndDateSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    place = serializer.validated_data['place']
    date = serializer.validated_data['date']

    refresh_token = request.data.get('refresh_token')
    if not refresh_token or validate_refresh_token(refresh_token) is None:
        return Response({'error': 'Invalid or missing refresh token.'}, status=status.HTTP_401_UNAUTHORIZED)


    iata_code = get_iata_code(place)
    if not iata_code:
        return Response({'error': 'Place not found'}, status=status.HTTP_400_BAD_REQUEST)

    access_token = get_amadeus_access_token()
    if not access_token:
        return Response({'error': 'Failed to obtain Amadeus access token'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    headers = {'Authorization': f'Bearer {access_token}'}
    
    iata_codes = ['DEL', 'BLR', 'BOM','HYD','COK','TRV']  # Example set of IATA codes for other places
    incoming_flights_count = 0
    outgoing_flights_count = 0

    for code in iata_codes:
        if code != iata_code:  # Skip the place itself
            outgoing_params = {
                'originLocationCode': iata_code,
                'destinationLocationCode': code,
                'departureDate': date,
                'adults': 1
            }
            incoming_params = {
                'originLocationCode': code,
                'destinationLocationCode': iata_code,
                'departureDate': date,
                'adults': 1
            }

            outgoing_data = fetch_flight_data(f"{settings.AMADEUS_BASE_URL}/v2/shopping/flight-offers", outgoing_params, headers)
            incoming_data = fetch_flight_data(f"{settings.AMADEUS_BASE_URL}/v2/shopping/flight-offers", incoming_params, headers)

            outgoing_flights_count += len(outgoing_data.get('data', [])) if outgoing_data else 0
            incoming_flights_count += len(incoming_data.get('data', [])) if incoming_data else 0

    result = {
        'place': place,
        'date': date,
        'incoming_flights_count': incoming_flights_count,
        'outgoing_flights_count': outgoing_flights_count,
        'total_flights': incoming_flights_count + outgoing_flights_count
    }
    
    response_serializer = FlightByPlaceAndDateResponseSerializer(data=result)
    user = Userdetails.user
    log_user_activity(user, 'POST', '/api/flight/by-place-and-date/')
    if response_serializer.is_valid():
        return Response(response_serializer.validated_data, status=status.HTTP_200_OK)
    else:
        logger.error(f"Response serializer errors: {response_serializer.errors}")
        return Response(response_serializer.errors, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['POST'])
def flight_summary_view(request):
    serializer = FlightSummarySerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    date = datetime.now().date()

    refresh_token = request.data.get('refresh_token')
    if not refresh_token or validate_refresh_token(refresh_token) is None:
        return Response({'error': 'Invalid or missing refresh token.'}, status=status.HTTP_401_UNAUTHORIZED)

    place_names = ['Pune', 'Goa', 'Kolkata', 'Chennai', 'Hyderabad']

    # Map place names to IATA codes
    iata_codes = [get_iata_code(name) for name in place_names]
    if None in iata_codes:
        return Response({'error': 'One or more place names could not be mapped to IATA codes.'}, status=status.HTTP_400_BAD_REQUEST)

    # Create and save FlightRequest record
    flight_request = FlightRequest.objects.create(
        request_type='summary',
        date=date,
        iata_codes=iata_codes
    )

    headers = {'Authorization': f'Bearer {get_amadeus_access_token()}'}
    result = {}

    iata_to_place = {get_iata_code(name): name for name in place_names}

    for code in iata_codes:
        incoming_flights_count, outgoing_flights_count = 0, 0

        for destination_code in iata_codes:
            if destination_code != code:  # Skip the place itself
                outgoing_params = {
                    'originLocationCode': code,
                    'destinationLocationCode': destination_code,
                    'departureDate': date,
                    'adults': 1
                }
                incoming_params = {
                    'originLocationCode': destination_code,
                    'destinationLocationCode': code,
                    'departureDate': date,
                    'adults': 1
                }
            
                outgoing_data = fetch_flight_data(f"{settings.AMADEUS_BASE_URL}/v2/shopping/flight-offers", outgoing_params, headers)
                incoming_data = fetch_flight_data(f"{settings.AMADEUS_BASE_URL}/v2/shopping/flight-offers", incoming_params, headers)

                if outgoing_data:
                    outgoing_flights_count += len(outgoing_data.get('data', []))
                if incoming_data:
                    incoming_flights_count += len(incoming_data.get('data', []))
            
        place_name = iata_to_place.get(code, code)

        result[place_name] = {
            'date': date,
            'incoming_flights': incoming_flights_count,
            'outgoing_flights': outgoing_flights_count,
            'total_flights': incoming_flights_count + outgoing_flights_count
        }

        # Save flight summary
        FlightSummary.objects.create(
            flight_request=flight_request,
            place=place_name,  # Save the place name instead of the IATA code
            date=date,
            incoming_flights_count=incoming_flights_count,
            outgoing_flights_count=outgoing_flights_count,
            total_flights=incoming_flights_count + outgoing_flights_count
        )
    user = Userdetails.user
    log_user_activity(user, 'POST', '/api/flight-summary/')
    return Response(result)