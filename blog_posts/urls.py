from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    UserViewSet,
    PostViewSet,
    CommentViewSet,
    LikePostView,
    LoginView,
    RegisterView,
    TestTokenView,
    DeleteUserView,
    UpdateUserView,
    DeleteAllUsersView
)

# Default Router for standard CRUD routes
router = DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'posts', PostViewSet)
router.register(r'comments', CommentViewSet)

urlpatterns = [
    # Include routes from DefaultRouter
    path('', include(router.urls)),

    # Authentication Endpoints
    path('login/', LoginView.as_view(), name='login'),
    path('register/', RegisterView.as_view(), name='register'),
    path('test/', TestTokenView.as_view(), name='test'),

    # User Management Endpoints
    path('delete-user/<int:pk>/', DeleteUserView.as_view(), name='delete-user'),
    path('update-user/<int:pk>/', UpdateUserView.as_view(), name='update-user'),
    path('delete-all-users/', DeleteAllUsersView.as_view(), name='delete-all-users'),

    # Post Like Endpoint
    path('posts/<int:post_id>/like/', LikePostView.as_view(), name='like-post'),

    # Custom Comment Endpoints
    path('posts/<int:post_id>/comments/', CommentViewSet.as_view({'post': 'create'}), name='create-comment'),
    path('comments/<int:pk>/', CommentViewSet.as_view({'put': 'update', 'delete': 'destroy'}), name='update-delete-comment'),
]
