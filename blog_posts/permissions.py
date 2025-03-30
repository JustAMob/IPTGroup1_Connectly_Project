from rest_framework import permissions

class IsAdminUser(permissions.BasePermission):
    """
    Custom permission to only allow admin users to access the view.
    """
    def has_permission(self, request, view):
        return request.user and request.user.role == 'admin'

class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Custom permission to only allow the owner of the post or admin users to access the view.
    """
    def has_object_permission(self, request, view, obj):
        if request.user.role == 'admin':  # Admin can access any object
            return True
        return obj.author == request.user  # Owner of the post can access
