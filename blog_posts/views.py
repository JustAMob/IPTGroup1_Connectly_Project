import logging
from django.shortcuts import get_object_or_404
from rest_framework import status, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from .models import User, Post, Comment, Like
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
    queryset = Post.objects.select_related('author').all()
    serializer_class = PostSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)

    def list(self, request, *args, **kwargs):
        logger.info(f"User: {request.user}, Authenticated: {request.user.is_authenticated}")
        return super().list(request, *args, **kwargs)


# Comment ViewSet
class CommentViewSet(viewsets.ModelViewSet):
    queryset = Comment.objects.select_related('author', 'post').all()
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
        
        if created:
            return Response({'message': 'Post liked.'}, status=status.HTTP_201_CREATED)
        else:
            like.delete()
            return Response({'message': 'Post unliked.'}, status=status.HTTP_204_NO_CONTENT)


# Login View using DRF authentication (Improved Security)
class LoginView(APIView):
    permission_classes = []

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        
        logger.info(f"Login attempt - Username: {username}")  # Removed password from logs
        user = User.objects.filter(username=username).first()
        
        if user and user.check_password(password):
            refresh = RefreshToken.for_user(user)
            logger.info(f"Login successful for {username}")
            return Response({
                'access': str(refresh.access_token),
                'refresh': str(refresh),
            })
        logger.warning(f"Login failed for {username} - Invalid credentials")
        return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)


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
    permission_classes = [IsAdminUser]  # Only admin users can delete users

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
    permission_classes = [IsAdminUser]

    def delete(self, request, pk, *args, **kwargs):
        user = get_object_or_404(User, id=pk)
        if user.is_superuser:
            return Response({"error": "Cannot delete superuser."}, status=status.HTTP_403_FORBIDDEN)

        user.delete()
        return Response({"message": f"User {user.username} deleted successfully."}, status=status.HTTP_204_NO_CONTENT)


# Update User View (Improved Error Handling)
class UpdateUserView(BaseAuthenticatedAPIView):
    def put(self, request, pk, *args, **kwargs):
        try:
            user = User.objects.get(id=pk)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserUpdateSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
