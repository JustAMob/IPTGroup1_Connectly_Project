from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import LoginView, RegisterView, DeleteUserView  
from .views import TestTokenView
from .views import (
    UserViewSet,
    PostViewSet,
    CommentViewSet,
    LikePostView,
    RegisterView,
    TestTokenView,
    DeleteUserView,
    UpdateUserView,
    NewsFeedView,
    FollowUserView,
    DeleteAllUsersView
)

# Default Router for CRUD Endpoints
router = DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'posts', PostViewSet)
router.register(r'comments', CommentViewSet)

urlpatterns = [
    # Include Router URLs
    path('', include(router.urls)),

    # Authentication Endpoints
    path('login/', LoginView.as_view(), name='login'),
    path('register/', RegisterView.as_view(), name='register'),
    path('test/', TestTokenView.as_view(), name='test'),

    # User Management
    path('delete-user/<int:pk>/', DeleteUserView.as_view(), name='delete-user'),
    path('update-user/<int:pk>/', UpdateUserView.as_view(), name='update-user'),
    path('delete-all-users/', DeleteAllUsersView.as_view(), name='delete-all-users'),

    # Post Like
    path('posts/<int:post_id>/like/', LikePostView.as_view(), name='like-post'),

    # Comment Endpoints
    path('posts/<int:post_id>/comments/', CommentViewSet.as_view({'post': 'create'}), name='create-comment'),
    path('comments/<int:pk>/', CommentViewSet.as_view({'put': 'update', 'delete': 'destroy'}), name='update-delete-comment'),

    # News Feed & Following
    path('feed/', NewsFeedView.as_view(), name='news-feed'),
    path('follow/', FollowUserView.as_view(), name='follow_user'),
]
