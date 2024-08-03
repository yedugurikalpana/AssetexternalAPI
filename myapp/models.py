from django.db import models

# Create your models here.
from django.db import models

# Create your models here.
from django.contrib.auth.models import AbstractUser
from django.db import models
import secrets
from datetime import timedelta
from django.utils import timezone
 
class CustomUser(AbstractUser):
    is_verified = models.BooleanField(default=False)
    one_time_token = models.CharField(max_length=255, blank=True, null=True)

    verification_code = models.CharField(max_length=6, blank=True, null=True)
    verification_code_created_at = models.DateTimeField(blank=True, null=True)

    def generate_verification_code(self):
        self.verification_code = secrets.token_hex(3).upper()  # Generate a 6-character verification code
        self.verification_code_created_at = timezone.now()
        self.save()

    def is_verification_code_valid(self):
        if not self.verification_code or not self.verification_code_created_at:
            return False
        code_expiry = self.verification_code_created_at + timedelta(minutes=5)
        return timezone.now() <= code_expiry

from django.db import models

class FlightRequest(models.Model):
    REQUEST_TYPE_CHOICES = [
        ('by_date', 'By Date'),
        ('by_place', 'By Place'),
        ('both', 'Both Place and Date'),
        ('summary','By Summary'),
    ]

    request_type = models.CharField(max_length=10, choices=REQUEST_TYPE_CHOICES)
    date = models.DateField(null=True, blank=True)
    iata_codes = models.JSONField(null=True, blank=True)  # Store IATA codes as a JSON array

    def __str__(self):
        return f"Flight Request: {self.request_type} on {self.date}"

class FlightSummary(models.Model):
    flight_request = models.ForeignKey(FlightRequest, on_delete=models.CASCADE)
    place = models.CharField(max_length=3)
    date = models.DateField()
    incoming_flights_count = models.IntegerField()
    outgoing_flights_count = models.IntegerField()
    total_flights = models.IntegerField()

    def __str__(self):
        return f"Flight Summary for {self.place} on {self.date}"

from django.utils import timezone
import pytz
from django.conf import settings

class UserActivityLog(models.Model):
    user = models.ForeignKey('myapp.CustomUser', on_delete=models.CASCADE)
    endpoint = models.CharField(max_length=255)
    method = models.CharField(max_length=10)
    timestamp = models.DateTimeField(default=timezone.now)
    timezone = models.CharField(max_length=50)

    def __str__(self):
        return f"{self.user} - {self.endpoint} - {self.timestamp} - {self.method}"