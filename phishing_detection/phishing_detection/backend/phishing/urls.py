from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import AnalyzePDF, ServePDFView, RegisterView, UserProfileView, UserProfileUpdateView, LogoutView, VerifyEmailView

urlpatterns = [
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),  # Login
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),  # Token refresh
    path('register/', RegisterView.as_view(), name='register'),
    path('analyze-pdf/', AnalyzePDF.as_view(), name='analyze_pdf'),
    path('serve-pdf/<str:filename>/', ServePDFView.as_view(), name='serve-pdf'),
    path('verify-email/<str:uidb64>/<str:token>/', VerifyEmailView.as_view(), name='verify-email'),
    path('user-profile/', UserProfileView.as_view(), name='user-profile'),
    path('user-profile/update/', UserProfileUpdateView.as_view(), name='user-profile-update'),
    path('logout/', LogoutView.as_view(), name='logout'),
]