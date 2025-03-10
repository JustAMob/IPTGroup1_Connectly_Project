from django.contrib import admin
from django.urls import path, include  # 'include' is needed to link app URLs
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.http import HttpResponseRedirect


urlpatterns = [
    path('admin/', admin.site.urls),

    # Include blog_posts app URLs
    path('api/', include('blog_posts.urls')),  # This will route all blog_posts URLs

    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # JWT Authentication endpoints
    path('', lambda request: HttpResponseRedirect('/api/')), 
]
