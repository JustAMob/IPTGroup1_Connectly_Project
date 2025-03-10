from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from blog_posts.models import Post, Comment  # Adjusted to your app name

class Command(BaseCommand):
    help = "Create default groups and permissions"

    def handle(self, *args, **kwargs):
        # Create Admin Group
        admin_group, created = Group.objects.get_or_create(name='Admin')
        if created:
            self.stdout.write(self.style.SUCCESS('Admin group created'))
        else:
            self.stdout.write(self.style.WARNING('Admin group already exists'))

        # Assign all permissions to Admin group
        admin_permissions = Permission.objects.all()
        admin_group.permissions.set(admin_permissions)
        self.stdout.write(self.style.SUCCESS('Admin permissions set'))

        # Create Regular User Group
        regular_group, created = Group.objects.get_or_create(name='Regular User')
        if created:
            self.stdout.write(self.style.SUCCESS('Regular User group created'))
        else:
            self.stdout.write(self.style.WARNING('Regular User group already exists'))

        # Assign limited permissions to Regular User group
        post_content_type = ContentType.objects.get_for_model(Post)
        comment_content_type = ContentType.objects.get_for_model(Comment)

        regular_permissions = Permission.objects.filter(
            content_type__in=[post_content_type, comment_content_type]
        ).exclude(codename__in=[
            'delete_user', 'change_user', 'add_user', 'view_user'
        ])

        regular_group.permissions.set(regular_permissions)
        self.stdout.write(self.style.SUCCESS('Regular User permissions set'))

        self.stdout.write(self.style.SUCCESS('Groups and permissions setup complete'))
