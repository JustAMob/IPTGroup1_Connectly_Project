from django.test import TestCase
from django.contrib.auth import get_user_model
from .models import Post
from django.db.models import Q

User = get_user_model()


class BlogPostTests(TestCase):

    def setUp(self):
        # Create a test user
        self.user = User.objects.create_user(
            username='testuser',
            email='test99@example.com',
            password='testpassword123'
        )
        self.admin = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='adminpassword123',
            role='admin'
        )   

    def test_create_post(self):
        # Create a post for the test user
        post = Post.objects.create(
            content='This is a test post',
            author=self.user
        )
        self.assertEqual(post.content, 'This is a test post')
        self.assertEqual(post.author.username, 'testuser')

    def test_private_post_access(self):
        # Create private post
        private_post = Post.objects.create(
            content='Private content',
            author=self.user,
            privacy='private'
        )
        
        # Owner can access
        self.client.force_login(self.user)
        response = self.client.get(f'/posts/{private_post.id}/')
        self.assertEqual(response.status_code, 200)
        
        # Admin can access
        self.client.force_login(self.admin)
        response = self.client.get(f'/posts/{private_post.id}/')
        self.assertEqual(response.status_code, 200)
        
        # Other user cannot access
        self.client.force_login(self.other_user)
        response = self.client.get(f'/posts/{private_post.id}/')
        self.assertEqual(response.status_code, 403)

    def test_news_feed_privacy(self):
        # Create posts with different privacy settings
        public_post = Post.objects.create(
            content='Public content',
            author=self.user,
            privacy='public'
        )
        private_post = Post.objects.create(
            content='Private content',
            author=self.user,
            privacy='private'
        )
        
        # Make other_user follow testuser
        Follow.objects.create(user=self.other_user, followed_user=self.user)
        
        # Check news feed for other_user
        self.client.force_login(self.other_user)
        response = self.client.get('/feed/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 1)  # Should only see public post