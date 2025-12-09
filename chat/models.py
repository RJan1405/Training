# chat/models.py
import os
from datetime import datetime
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import pre_delete, post_save
from django.dispatch import receiver
from django.conf import settings
from django.utils import timezone
import uuid


def message_file_path(instance, filename):
    """Generate file path for uploaded files"""
    ext = filename.split('.')[-1]
    filename = f"{instance.id}_{instance.sender.id}.{ext}"
    # Use current datetime if instance.timestamp is None
    timestamp = instance.timestamp if instance.timestamp else datetime.now()
    return os.path.join('messages', timestamp.strftime('%Y/%m/%d'), filename)


class Project(models.Model):
    """Groups/Projects for team chat"""
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True, null=True)
    members = models.ManyToManyField(User, related_name='projects')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name='created_projects')

    class Meta:
        ordering = ['name']
        verbose_name_plural = 'Projects'

    def __str__(self):
        return self.name


class Message(models.Model):
    """Message model for both DM and project chats

    Messages are stored encrypted (encrypted_text BinaryField).
    Access `message.text` to get decrypted text; setting `message.text = '...'`
    will encrypt automatically before save.
    """

    # Sender (required)
    sender = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='sent_messages'
    )

    # For DMs only
    receiver = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='received_messages',
        null=True,
        blank=True
    )

    # For project chat only
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name='messages',
        null=True,
        blank=True
    )

    # ENCRYPTED: Message content stored as binary
    encrypted_text = models.BinaryField(
        null=True,
        blank=True,
        help_text="Encrypted message content (Fernet)"
    )

    # File attachment
    file = models.FileField(
        upload_to=message_file_path,
        null=True,
        blank=True,
        help_text="Supported: images, PDFs, documents"
    )

    # Message this one replies to (thread reference)
    reply_to = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='replies'
    )

    # Metadata
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    is_read = models.BooleanField(default=False, db_index=True)

    class Meta:
        ordering = ['timestamp']
        indexes = [
            models.Index(fields=['sender', 'timestamp']),
            models.Index(fields=['receiver', 'is_read']),
            models.Index(fields=['project', 'timestamp']),
            models.Index(fields=['reply_to']),
        ]

    def __str__(self):
        if self.project:
            return f"Project message: {self.sender} in {self.project}"
        return f"DM: {self.sender} → {self.receiver}"

    # ENCRYPTION PROPERTY: Automatic decryption
    @property
    def text(self):
        """Decrypt message text from encrypted_text"""
        if not self.encrypted_text:
            return ""
        try:
            # import locally to avoid circular import on startup
            from .utils.encryption import decrypt_message
            return decrypt_message(self.encrypted_text)
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(
                f"Failed to decrypt message {getattr(self, 'id', '<new>')}: {str(e)}")
            return "[Decryption Error]"

    @text.setter
    def text(self, value):
        """Encrypt message text and store in encrypted_text"""
        if value is None:
            self.encrypted_text = None
            return
        try:
            from .utils.encryption import encrypt_message
            self.encrypted_text = encrypt_message(value)
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to encrypt message: {str(e)}")
            raise

    def clean(self):
        from django.core.exceptions import ValidationError
        # Either receiver OR project must be set, not both
        if (self.receiver and self.project) or (not self.receiver and not self.project):
            raise ValidationError(
                "Message must have either receiver OR project, not both")

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)


class UserProfile(models.Model):
    """Extended user profile for additional features"""
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name='profile')
    is_online = models.BooleanField(default=False, db_index=True)
    last_seen = models.DateTimeField(auto_now=True)
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)

    class Meta:
        verbose_name_plural = 'User Profiles'

    def __str__(self):
        return f"{self.user.username}'s Profile"


class BlockedUser(models.Model):
    """Represents a user blocking another user."""
    blocker = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='blocked_users')
    blocked = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='blocked_by')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('blocker', 'blocked')
        indexes = [
            models.Index(fields=['blocker', 'blocked']),
        ]

    def __str__(self):
        return f"{self.blocker_id}→{self.blocked_id}"


# SIGNALS: Auto-create UserProfile
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    try:
        instance.profile.save()
    except UserProfile.DoesNotExist:
        UserProfile.objects.create(user=instance)


# SIGNALS: Cleanup uploaded files on message deletion
@receiver(pre_delete, sender=Message)
def delete_message_file(sender, instance, **kwargs):
    if instance.file:
        instance.file.delete(save=False)


User = settings.AUTH_USER_MODEL


class Meeting(models.Model):
    STATUS_CHOICES = [
        ('scheduled', 'Scheduled'),
        ('started', 'Started'),
        ('ended', 'Ended'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    host = models.ForeignKey(
        User, related_name='hosted_meetings', on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    scheduled_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='scheduled')
    created_at = models.DateTimeField(auto_now_add=True)
    ended=models.BooleanField(default=False)
    def start(self):
        self.status = 'started'
        self.save(update_fields=['status'])


class MeetingInvitation(models.Model):
    meeting = models.ForeignKey(
        Meeting, related_name='invitations', on_delete=models.CASCADE)
    user = models.ForeignKey(
        User, related_name='meeting_invitations', on_delete=models.CASCADE)
    invited_by = models.ForeignKey(
        User, related_name='sent_meeting_invitations', on_delete=models.CASCADE)
    accepted = models.BooleanField(default=False)
    invited_at = models.DateTimeField(auto_now_add=True)
    responded_at = models.DateTimeField(null=True, blank=True)
    token = models.CharField(max_length=64, blank=True,
                             null=True)  # optional join token

    class Meta:
        unique_together = ('meeting', 'user')
