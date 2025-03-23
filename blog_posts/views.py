import logging
import time
from django.contrib.auth import logout
from django.contrib.auth import login
from django.contrib.auth import authenticate
from django.db import transaction
from django.shortcuts import redirect
from social_django.utils import load_strategy
from social_core.backends.google import GoogleOAuth2
from social_core.exceptions import AuthException
from django.shortcuts import get_object_or_404
from django.core.cache import cache
from rest_framework.throttling import UserRateThrottle
from rest_framework import status, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.pagination import PageNumberPagination
from rest_framework.generics import ListAPIView
from .models import User, Post, Comment, Like
from .models import Follow
from .serializers import (
    UserSerializer, 
    UserRegisterSerializer, 
    PostSerializer, 
    CommentSerializer,
    UserUpdateSerializer
)

logger = logging.getLogger(__name__)  # Properly initialized logger


# Base Class for Reusability
class BaseAuthenticatedAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]


# User ViewSet
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)


# User List View (Refactored)
class UserListView(BaseAuthenticatedAPIView):
    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


# Post ViewSet
class PostViewSet(viewsets.ModelViewSet):
    queryset = Post.objects.select_related('author').only('id', 'author_id', 'content', 'created_at')
    serializer_class = PostSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)


# Comment ViewSet
class CommentViewSet(viewsets.ModelViewSet):
    queryset = Comment.objects.select_related('author', 'post').only('id', 'author_id', 'post_id', 'created_at')
    serializer_class = CommentSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        post_id = self.kwargs.get('post_id')
        post = get_object_or_404(Post, id=post_id)
        serializer.save(author=self.request.user, post=post)


# Like/Unlike a Post (Refactored)
class LikePostView(BaseAuthenticatedAPIView):
    def post(self, request, post_id):
        post = get_object_or_404(Post, id=post_id)
        like, created = Like.objects.get_or_create(post=post, user=request.user)

        if not created:
            # If like already exists, delete it (unlike the post)
            like.delete()
            return Response({"message": "Post unliked."}, status=status.HTTP_200_OK)

        return Response({'message': 'Post liked.'}, status=status.HTTP_201_CREATED)



# Login View using DRF authentication (Improved Security)
class LoginView(APIView):
    permission_classes = []
    throttle_classes = [UserRateThrottle]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        logger.info(f"Login attempt - Username: {username}")

        user = authenticate(username=username, password=password)

        if not user:
            logger.warning(f"Login failed for {username} - Invalid credentials")
            logger.error(f"Authentication failed for user {username}")
            return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
            
           

        refresh = RefreshToken.for_user(user)
        logger.info(f"Login successful for {username}")
        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        })
    
# Register User View
class RegisterView(APIView):
    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Test Token View
class TestTokenView(BaseAuthenticatedAPIView):
    def get(self, request):
        return Response({"message": "Token is valid!"})


# Delete All Users View (Enhanced Security)
class DeleteAllUsersView(BaseAuthenticatedAPIView):
    permission_classes = [IsAuthenticated]  

    def delete(self, request, *args, **kwargs):
        try:
            logger.info("Delete all users request received")
            users_to_delete = User.objects.exclude(is_superuser=True)
            deleted_count, _ = users_to_delete.delete()  # Deletes the users

            logger.info(f"{deleted_count} users deleted successfully.")
            return Response({"message": f"{deleted_count} users deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            logger.error(f"Error occurred: {str(e)}")
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# Delete Single User View (Improved with get_object_or_404)
class DeleteUserView(BaseAuthenticatedAPIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk, *args, **kwargs):
        user = get_object_or_404(User, id=pk)
        if user.is_superuser:
            return Response({"error": "Cannot delete superuser."}, status=status.HTTP_403_FORBIDDEN)

        user.delete()
        return Response({"message": f"User {user.username} deleted successfully."}, status=status.HTTP_204_NO_CONTENT)


# Update User View (Improved Error Handling)
class UpdateUserView(BaseAuthenticatedAPIView):
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

# News Feed View
class NewsFeedView(ListAPIView):
    serializer_class = PostSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = PostPagination

    def get_queryset(self):
        user = self.request.user
        cache_key = f'user_feed_{user.id}'
        posts = cache.get(cache_key)

        if posts is None:
            followed_users = Follow.objects.filter(user=user).values_list('followed_user', flat=True)
            posts = list(Post.objects.filter(author__in=followed_users)
                        .select_related('author')
                        .prefetch_related('comments')
                        .order_by('-created_at'))
            cache.set(cache_key, posts, timeout=900)  # Cache for 15 min

        return posts  # Return cached queryset


CACHE_THROTTLE = {}

def invalidate_user_feed_cache(user):
    """Function to invalidate the user's feed cache with a simple throttle."""
    now = time.time()
    user_cache_key = f"user_cache_throttle_{user.id}"

    last_invalidated = CACHE_THROTTLE.get(user_cache_key, 0)
    if now - last_invalidated < 30:  # Prevent invalidating more than once every 30 sec
        return

    cache.delete(f'user_feed_{user.id}')
    CACHE_THROTTLE[user_cache_key] = now
    logger.info(f"Cache invalidated for user {user.id}.")


class FollowUserView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]  # Limit login attempts

    def post(self, request):
        followed_user_id = request.data.get('followed_user_id')

        followed_user = get_object_or_404(User, id=followed_user_id)

        if followed_user == request.user:
            return Response({'error': 'You cannot follow yourself.'}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():  # Ensure atomicity
            if Follow.objects.filter(user=request.user, followed_user=followed_user).exists():
                return Response({'error': 'You are already following this user.'}, status=status.HTTP_400_BAD_REQUEST)

            Follow.objects.create(user=request.user, followed_user=followed_user)

        invalidate_user_feed_cache(request.user)
        invalidate_user_feed_cache(followed_user)

        logger.info(f"{request.user.username} is now following {followed_user.username}.")

        return Response({'message': f'You are now following {followed_user.username}.'}, status=status.HTTP_201_CREATED)
    
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




