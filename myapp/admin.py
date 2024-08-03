from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, UserActivityLog

# CustomUser Admin
class CustomUserAdmin(UserAdmin):
    model = CustomUser
    fieldsets = UserAdmin.fieldsets + (
        (None, {'fields': ('is_verified', 'one_time_token')}),
    )

admin.site.register(CustomUser, CustomUserAdmin)

# UserActivityLog Admin
class UserActivityLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'method', 'endpoint', 'timestamp', 'timezone')
    list_filter = ('method', 'endpoint', 'timezone')
    search_fields = ('user__username', 'endpoint', 'method')

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        # Exclude admin users from logs
        return qs.filter(user__is_superuser=False)

admin.site.register(UserActivityLog, UserActivityLogAdmin)
