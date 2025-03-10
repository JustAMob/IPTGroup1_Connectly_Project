from django.test import TestCase
from django.contrib.auth import get_user_model
from .models import Post

User = get_user_model()

class BlogPostTests(TestCase):

    def setUp(self):
        # Create a test user
        self.user = User.objects.create_user(
            username='testuser',
            email='test99@example.com',
            password='testpassword123'
        )

    def test_create_post(self):
        # Create a post for the test user
        post = Post.objects.create(
            content='This is a test post',
            author=self.user
        )
        self.assertEqual(post.content, 'This is a test post')
        self.assertEqual(post.author.username, 'testuser')
