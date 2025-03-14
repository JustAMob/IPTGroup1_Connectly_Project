from argon2 import PasswordHasher
from django.db import models
from django.db.models.signals import post_save
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.dispatch import receiver
from django.contrib.auth.hashers import make_password

# Custom User Model
class User(AbstractUser):
    password = models.CharField(max_length=255)

    groups = models.ManyToManyField(
        Group, 
        related_name='custom_user_groups',  
        blank=True
    )
    user_permissions = models.ManyToManyField(
        Permission, 
        related_name='custom_user_permissions', 
        blank=True
    )

    def save(self, *args, **kwargs):
        if self.pk is None or not User.objects.get(pk=self.pk).password == self.password:
            self.set_password(self.password)  # Preferred Django way
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username

# Signal to automatically add a newly created user to a group
def assign_user_to_group(sender, instance, created, **kwargs):
    if created:
        group_name = 'Admin' if instance.is_superuser else 'Regular User'
        try:
            group = Group.objects.get(name=group_name)
            instance.groups.add(group)
        except Group.DoesNotExist:
            pass

post_save.connect(assign_user_to_group, sender=User)  # Registering the signal

# Follow Model for User Relationships
class Follow(models.Model):
    user = models.ForeignKey(User, related_name='followers', on_delete=models.CASCADE)
    followed_user = models.ForeignKey(User, related_name='following', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'followed_user')

    def __str__(self):
        return f"{self.user.username} follows {self.followed_user.username}"        

# Post Model
class Post(models.Model):
    content = models.TextField()
    author = models.ForeignKey(User, related_name='posts', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"Post by {self.author.username} at {self.created_at}"

# Comment Model
class Comment(models.Model):
    text = models.TextField()
    author = models.ForeignKey(User, related_name='comments', on_delete=models.CASCADE)
    post = models.ForeignKey(Post, related_name='comments', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Comment by {self.author.username} on Post {self.post.id}"

# Like Model
class Like(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='likes')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='likes')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['post', 'user'], name='unique_like')
        ]

    def __str__(self):
        return f"{self.user.username} liked Post {self.post.id}"

# Singleton Pattern for Password Management
class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

class PasswordSingleton(metaclass=Singleton):
    def __init__(self, password):
        self.password = password

class PasswordClass:
    def __init__(self, password):
        self.password = password

class PasswordFactory:
    def __init__(self):
        self._creators = {}

    def register_class(self, key, creator):
        self._creators[key] = creator

    def create_instance(self, key, *args, **kwargs):
        creator = self._creators.get(key)
        if not creator:
            raise ValueError(f"Class not registered for key: {key}")
        return creator(*args, **kwargs)