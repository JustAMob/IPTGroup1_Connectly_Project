import logging
from .permissions import IsAdminUser, IsOwnerOrAdmin, CanViewPrivatePost
from rest_framework.permissions import AllowAny
from django.contrib.auth import logout, login, authenticate
from django.shortcuts import redirect, get_object_or_404
from django.shortcuts import render
from django.http import HttpResponse
from django.db import transaction
from django.db import models  
from django.db.models import Q
from django.core.cache import cache
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.contrib.auth.models import User
from rest_framework import status, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.pagination import PageNumberPagination
from .models import User, Post, Comment, Like
from .models import Follow
from .serializers import (
    UserSerializer, 
    PostSerializer, 
    CommentSerializer, 
    UserUpdateSerializer
)
from .permissions import IsAdminUser, IsOwnerOrAdmin

logger = logging.getLogger(__name__)

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @method_decorator(cache_page(60*15))  # Cache for 15 minutes
    def list(self, request):
        cache_key = 'users_list'
        users = cache.get(cache_key)
        
        if not users:
            users = User.objects.all()
            cache.set(cache_key, users, 60*15)  # Cache for 15 minutes
            logger.info(f"User list cache miss - fetching from DB")
        
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

    def perform_update(self, serializer):
        instance = serializer.save()
        cache.delete('users_list')  # Invalidate cache when user data changes
        logger.info(f"Invalidated users_list cache due to user update")

class PostViewSet(viewsets.ModelViewSet):
    queryset = Post.objects.select_related('author').only('id', 'author_id', 'content', 'created_at', 'privacy')
    serializer_class = PostSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]

    @method_decorator(cache_page(60*5))  # Cache for 5 minutes (shorter duration as posts change more frequently)
    def list(self, request):
        user = self.request.user
        cache_key = f'posts_list_{user.id}'  # User-specific cache key
        posts = cache.get(cache_key)
        
        if not posts:
            posts = self.get_queryset()
            cache.set(cache_key, posts, 60*5)
            logger.info(f"Post list cache miss for user {user.id}")
        
        serializer = PostSerializer(posts, many=True)
        return Response(serializer.data)

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)
        cache.delete(f'posts_list_{self.request.user.id}')  # Invalidate cache when new post is created
        cache.delete('news_feed_*')  # Invalidate all news feed caches (using wildcard)
        logger.info(f"Invalidated post caches due to new post creation")

    def perform_destroy(self, instance):
        super().perform_destroy(instance)
        cache.delete(f'posts_list_{instance.author.id}')
        cache.delete(f'post_detail_{instance.id}')
        cache.delete('news_feed_*')
        logger.info(f"Invalidated post caches due to post deletion")

class CommentViewSet(viewsets.ModelViewSet):
    queryset = Comment.objects.select_related('author', 'post')
    serializer_class = CommentSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]

    @method_decorator(cache_page(60*10))
    def list(self, request, post_id=None):
        cache_key = f'comments_list_{post_id}'
        comments = cache.get(cache_key)
        
        if not comments:
            comments = self.get_queryset().filter(post_id=post_id)
            cache.set(cache_key, comments, 60*10)
            logger.info(f"Comments cache miss for post {post_id}")
        
        serializer = CommentSerializer(comments, many=True)
        return Response(serializer.data)

    def perform_create(self, serializer):
        post_id = self.kwargs.get('post_id')
        serializer.save(author=self.request.user, post_id=post_id)
        cache.delete(f'comments_list_{post_id}')  # Invalidate comments cache for this post
        logger.info(f"Invalidated comments cache for post {post_id}")

class LikePostView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, post_id):
        post = get_object_or_404(Post, id=post_id)
        like, created = Like.objects.get_or_create(post=post, user=request.user)

        if not created:
            like.delete()
            # Invalidate relevant caches
            cache.delete(f'post_detail_{post_id}')
            cache.delete(f'posts_list_{post.author.id}')
            cache.delete(f'news_feed_{request.user.id}')
            return Response({"message": "Post unliked."}, status=status.HTTP_200_OK)

        # Invalidate relevant caches
        cache.delete(f'post_detail_{post_id}')
        cache.delete(f'posts_list_{post.author.id}')
        cache.delete(f'news_feed_{request.user.id}')
        return Response({'message': 'Post liked.'}, status=status.HTTP_201_CREATED)


# Delete User View (For admin only) with RBAC applied
class DeleteUserView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser]  # Only admin can delete a user

    def delete(self, request, pk, *args, **kwargs):
        user = get_object_or_404(User, id=pk)
        if user.is_superuser:
            return Response({"error": "Cannot delete superuser."}, status=status.HTTP_403_FORBIDDEN)

        user.delete()
        return Response({"message": f"User {user.username} deleted successfully."}, status=status.HTTP_204_NO_CONTENT)


# Update User View (General user can update their own info; Admin can update any user)
class UpdateUserView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]  # Owner or Admin can update the user

    def put(self, request, pk):
        user = get_object_or_404(User, id=pk)
        serializer = UserUpdateSerializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Custom Pagination Class
class PostPagination(PageNumberPagination):
    page_size = 10  # Number of posts per page
    page_size_query_param = 'page_size'
    max_page_size = 100

class NewsFeedView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = PostPagination

    @method_decorator(cache_page(60*2))  # Cache for 2 minutes
    def get(self, request):
        user = request.user
        cache_key = f'news_feed_{user.id}'
        posts = cache.get(cache_key)
        
        if not posts:
            posts = Post.objects.filter(
                models.Q(author__in=user.following.all()) & 
                (models.Q(privacy='public') | models.Q(author=user))
            ).order_by('-created_at')
            cache.set(cache_key, posts, 60*2)
            logger.info(f"News feed cache miss for user {user.id}")
        
        page = self.paginate_queryset(posts)
        if page is not None:
            serializer = PostSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = PostSerializer(posts, many=True)
        return Response(serializer.data)


# Follow User View (RBAC for user following functionality)
class FollowUserView(APIView):
    permission_classes = [IsAuthenticated]  # Only authenticated users can follow others

    def post(self, request):
        followed_user_id = request.data.get('followed_user_id')

        followed_user = get_object_or_404(User, id=followed_user_id)

        if followed_user == request.user:
            return Response({'error': 'You cannot follow yourself.'}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():  # Ensure atomicity
            if Follow.objects.filter(user=request.user, followed_user=followed_user).exists():
                return Response({'error': 'You are already following this user.'}, status=status.HTTP_400_BAD_REQUEST)

            Follow.objects.create(user=request.user, followed_user=followed_user)

        logger.info(f"{request.user.username} is now following {followed_user.username}.")
        return Response({'message': f'You are now following {followed_user.username}.'}, status=status.HTTP_201_CREATED)

class LoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            return Response({
                'access': access_token,
                'refresh': str(refresh)
            }, status=200)
        
        return Response({"detail": "Invalid credentials"}, status=400)

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class TestTokenView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def get(self, request):
        return Response({"message": "Token is valid!"})

class DeleteAllUsersView(APIView):
    permission_classes = [IsAdminUser]  # Ensure that only admins can delete all users

    def delete(self, request, *args, **kwargs):
        # Prevent deletion of superuser accounts
        User.objects.exclude(is_superuser=True).delete()
        return Response({"message": "All non-superuser users have been deleted."}, status=status.HTTP_204_NO_CONTENT)

class GoogleLoginView(APIView):
    def get(self, request):
        strategy = load_strategy(request)
        backend = GoogleOAuth2(strategy=strategy)
        code = request.GET.get('code')

        if not code:
            return Response({"error": "Authorization code missing"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = backend.do_auth(code)
            if user and user.is_active:
                login(request, user)
                refresh = RefreshToken.for_user(user)
                return Response({
                    "message": "Login successful",
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                    "user": user.email
                })
            return Response({"error": "Authentication failed"}, status=status.HTTP_400_BAD_REQUEST)
        except AuthException as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class GoogleLogoutView(APIView):
    def get(self, request):
        logout(request)
        return Response({"message": "Logged out successfully"})

def invalidate_user_caches(user_id):
    """Invalidate all caches related to a specific user"""
    cache.delete(f'posts_list_{user_id}')
    cache.delete(f'news_feed_{user_id}')
    
    logger.info(f"Invalidated all caches for user {user_id}")

def invalidate_post_caches(post_id, author_id):
    """Invalidate all caches related to a specific post"""
    cache.delete(f'post_detail_{post_id}')
    cache.delete(f'posts_list_{author_id}')
    cache.delete(f'comments_list_{post_id}')
    
    cache.delete_pattern('news_feed_*')  # Using redis
    logger.info(f"Invalidated all caches for post {post_id}")