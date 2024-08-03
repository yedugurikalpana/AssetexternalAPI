from django.urls import path
from .views import RegisterView, VerifyView, LoginView,LoginVerifyView, flight_by_date_view, flight_by_place_view, flight_by_place_and_date_view,flight_summary_view
 
urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('verify/', VerifyView.as_view(), name='verify'),
    path('login/', LoginView.as_view(), name='login'),
    path('login/verify/', LoginVerifyView.as_view(), name='login_verify'),
    path('flights/by-date/', flight_by_date_view, name='flight_by_date'),
    path('flights/by-place/', flight_by_place_view, name='flight_by_place'),
    path('flights/by-place-and-date/', flight_by_place_and_date_view, name='flight_by_place_and_date'),
    path('flight-summary/', flight_summary_view, name='flight_summary_view'),
]

    
