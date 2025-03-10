from django.contrib import admin
from django.urls import path, include
from django.http import HttpResponseRedirect
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from blog_posts.views import GoogleLoginView, GoogleLogoutView

urlpatterns = [
    path('admin/', admin.site.urls),

    # Redirect root URL to API
    path('', lambda request: HttpResponseRedirect('/api/')),

    # Blog Posts App API Endpoints
    path('api/', include('blog_posts.urls')),

    # JWT Authentication Endpoints
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Social Authentication (Google OAuth)
    path('auth/', include('social_django.urls', namespace='social')),  # Social Auth Endpoints
    path('auth/login/google/', GoogleLoginView.as_view(), name="google_login"),
    path('auth/logout/', GoogleLogoutView.as_view(), name="logout"),
]
