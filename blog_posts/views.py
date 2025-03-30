import logging
from django.contrib.auth import logout, login, authenticate
from django.shortcuts import redirect, get_object_or_404
from django.db import transaction
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

# User ViewSet with RBAC applied
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)


# Post ViewSet with RBAC applied
class PostViewSet(viewsets.ModelViewSet):
    queryset = Post.objects.select_related('author').only('id', 'author_id', 'content', 'created_at')
    serializer_class = PostSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]  # Apply RBAC permission

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)


# Comment ViewSet with RBAC applied
class CommentViewSet(viewsets.ModelViewSet):
    queryset = Comment.objects.select_related('author', 'post').only('id', 'author_id', 'post_id', 'created_at')
    serializer_class = CommentSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]  # Apply RBAC permission

    def perform_create(self, serializer):
        post_id = self.kwargs.get('post_id')
        post = get_object_or_404(Post, id=post_id)
        serializer.save(author=self.request.user, post=post)


# Like/Unlike a Post with RBAC applied
class LikePostView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]  # No special role needed here, just authentication

    def post(self, request, post_id):
        post = get_object_or_404(Post, id=post_id)
        like, created = Like.objects.get_or_create(post=post, user=request.user)

        if not created:
            # If like already exists, delete it (unlike the post)
            like.delete()
            return Response({"message": "Post unliked."}, status=status.HTTP_200_OK)

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


# News Feed View with RBAC applied
class NewsFeedView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = PostPagination

    def get(self, request):
        user = request.user
        posts = Post.objects.filter(author__in=user.following.all()).order_by('-created_at')
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
