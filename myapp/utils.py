from .models import UserActivityLog
from django.utils import timezone

def log_user_activity(user, method, endpoint):
    if not user.is_superuser:  # Skip logging for admin users
        UserActivityLog.objects.create(
            user=user,
            method=method,
            endpoint=endpoint,
            timezone=timezone.get_current_timezone_name()  
        )
