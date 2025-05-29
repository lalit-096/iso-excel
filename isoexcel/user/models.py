from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils import timezone
import uuid

class CustomUserManager(BaseUserManager):
    def create_user(self, email=None, phone=None, password=None, **extra_fields):
        if not email and not phone:
            raise ValueError('User must have either email or phone')
        
        if email:
            email = self.normalize_email(email)
        
        user = self.model(email=email, phone=phone, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email=None, phone=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        
        return self.create_user(email, phone, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    THEME_CHOICES = [
        ('dark', 'Dark'),
        ('light', 'Light'),
    ]
    
    OTP_TYPE_CHOICES = [
        ('email', 'Email'),
        ('phone', 'Phone'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, null=True, blank=True)
    phone = models.CharField(max_length=15, unique=True, null=True, blank=True)
    username = models.CharField(max_length=30, unique=True, null=True, blank=True)
    
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    bio = models.TextField(blank=True)
    profile_visibility = models.BooleanField(default=True)
    
    theme_preference = models.CharField(max_length=5, choices=THEME_CHOICES, default='light')
    language_preference = models.CharField(max_length=10, default='en')
    timezone_preference = models.CharField(max_length=50, default='UTC')
    
    notification_preferences = models.JSONField(default=dict)
    
    terms_accepted = models.BooleanField(default=False)
    cookies_accepted = models.BooleanField(default=False)
    privacy_policy_accepted = models.BooleanField(default=False)
    
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    is_2fa_enabled = models.BooleanField(default=False)
    
    otp_code = models.CharField(max_length=6, blank=True, null=True)
    otp_expiry = models.DateTimeField(null=True, blank=True)
    otp_type = models.CharField(max_length=5, choices=OTP_TYPE_CHOICES, null=True, blank=True)
    
    social_auth_provider = models.CharField(max_length=50, blank=True, null=True)
    social_auth_id = models.CharField(max_length=255, blank=True, null=True)
    
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    
    account_recovery_email = models.EmailField(blank=True, null=True)
    account_recovery_phone = models.CharField(max_length=15, blank=True, null=True)
    
    session_key_list = models.JSONField(default=list)
    
    data_export_requested = models.DateTimeField(null=True, blank=True)
    
    date_joined = models.DateTimeField(default=timezone.now)
    
    objects = CustomUserManager()
    
    USERNAME_FIELD = 'email'  # This is the field used for authentication
    REQUIRED_FIELDS = []  # Email is already required as USERNAME_FIELD
    
    class Meta:
        verbose_name = 'user'
        verbose_name_plural = 'users'
        ordering = ['-date_joined']
    
    def __str__(self):
        return self.email or self.phone or str(self.id)
    
    def get_full_name(self):
        return f"{self.first_name} {self.last_name}".strip()
    
    def get_short_name(self):
        return self.first_name
    
    def save(self, *args, **kwargs):
        # Ensure at least one of email or phone is provided
        if not self.email and not self.phone:
            raise ValueError("User must have either email or phone")
        super().save(*args, **kwargs)


class LoginHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='login_history')
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device_info = models.TextField(blank=True, null=True)
    location = models.CharField(max_length=255, blank=True, null=True)
    
    class Meta:
        verbose_name = 'login history'
        verbose_name_plural = 'login histories'
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.user} - {self.timestamp}"
