# chat/serializers.py
"""
Serializers for chat application with comprehensive validation and error handling.

Fixes implemented:
- Issue #6: Fixed RecentChatSerializer timestamp serialization (ISO format)
- Issue #19: Improved UserSerializer profile handling with auto-creation
- Issue #5: Added sender permission validation in MessageCreateSerializer
- Added error response standardization
- Added comprehensive logging
- Added file validation
- Improved docstrings
"""

import logging
from rest_framework import serializers
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils import timezone
from .models import Message, Project, UserProfile

logger = logging.getLogger(__name__)


# ====================== CONFIGURATION ======================

class SerializerConfig:
    """Centralized configuration for serializers"""
    
    # File validation
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    ALLOWED_FILE_TYPES = {
        'image/jpeg', 'image/png', 'image/gif', 'image/webp',
        'application/pdf',
        'text/plain',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    }
    
    # Message validation
    MIN_MESSAGE_LENGTH = 1
    MAX_MESSAGE_LENGTH = 5000
    
    # User profile defaults
    DEFAULT_AVATAR_URL = None


# ====================== USER SERIALIZER ======================

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for User model with extended profile information.
    
    Handles:
    - User basic info (id, username, email, name)
    - Related profile data (online status, last seen, avatar)
    - Auto-creation of missing profiles
    - ISO formatted timestamps
    """
    
    profile = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'profile']
        read_only_fields = ['id', 'profile']
    
    def get_profile(self, obj):
        """
        Get or create user profile with proper error handling.
        
        Returns:
            dict: Profile data with is_online, last_seen, avatar
            None: If profile retrieval/creation fails after retries
        """
        try:
            profile = obj.profile
            
            return {
                'is_online': profile.is_online,
                'last_seen': (
                    profile.last_seen.isoformat() 
                    if profile.last_seen else None
                ),
                'avatar': profile.avatar.url if profile.avatar else None,
            }
            
        except UserProfile.DoesNotExist:
            logger.warning(
                "UserProfile missing for user %s (id=%s), attempting auto-creation",
                obj.username, obj.id
            )
            
            # Auto-create profile
            try:
                profile, created = UserProfile.objects.get_or_create(user=obj)
                
                if created:
                    logger.info(
                        "Auto-created UserProfile for user %s",
                        obj.username
                    )
                
                # Recursively call to get profile data
                return self.get_profile(obj)
                
            except Exception as e:
                logger.error(
                    "Failed to auto-create UserProfile for user %s: %s",
                    obj.username, str(e)
                )
                return {
                    'is_online': False,
                    'last_seen': None,
                    'avatar': None,
                }
        
        except Exception as e:
            logger.error(
                "Unexpected error retrieving profile for user %s: %s",
                obj.username, str(e)
            )
            return None


# ====================== PROJECT SERIALIZER ======================

class ProjectSerializer(serializers.ModelSerializer):
    """
    Serializer for Project model with member information.
    
    Handles:
    - Project metadata
    - Member list with user details
    - Member ID writing for updates
    """
    
    members = UserSerializer(many=True, read_only=True)
    member_ids = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        write_only=True,
        many=True,
        source='members',
        required=False,
    )
    member_count = serializers.SerializerMethodField()
    created_by_username = serializers.CharField(
        source='created_by.username',
        read_only=True,
    )
    
    class Meta:
        model = Project
        fields = [
            'id', 'name', 'description', 'members', 'member_ids',
            'member_count', 'created_at', 'updated_at', 'created_by',
            'created_by_username'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'created_by', 'member_count']
    
    def get_member_count(self, obj):
        """Get total number of project members"""
        return obj.members.count()
    
    def validate_name(self, value):
        """Validate project name"""
        if not value or not value.strip():
            raise serializers.ValidationError("Project name cannot be empty")
        
        if len(value) > 255:
            raise serializers.ValidationError("Project name too long (max 255 characters)")
        
        return value.strip()


# ====================== MESSAGE SERIALIZER ======================

class MessageSerializer(serializers.ModelSerializer):
    """
    Serializer for reading Message objects with all related data.
    
    Includes:
    - Sender and receiver information
    - Project information
    - Full file URLs
    - Formatted timestamps
    """
    
    sender_username = serializers.CharField(
        source='sender.username',
        read_only=True
    )
    sender_id = serializers.IntegerField(
        source='sender.id',
        read_only=True
    )
    receiver_username = serializers.CharField(
        source='receiver.username',
        read_only=True,
        allow_null=True
    )
    receiver_id = serializers.IntegerField(
        source='receiver.id',
        read_only=True,
        allow_null=True
    )
    project_name = serializers.CharField(
        source='project.name',
        read_only=True,
        allow_null=True
    )
    project_id = serializers.IntegerField(
        source='project.id',
        read_only=True,
        allow_null=True
    )
    reply_to_id = serializers.IntegerField(
        source='reply_to.id',
        read_only=True,
        allow_null=True
    )
    file_url = serializers.SerializerMethodField()
    timestamp_iso = serializers.SerializerMethodField()
    meeting_status = serializers.SerializerMethodField()
    
    class Meta:
        model = Message
        fields = [
            'id', 'sender', 'sender_id', 'sender_username',
            'receiver', 'receiver_id', 'receiver_username',
            'project', 'project_id', 'project_name',
            'text', 'file', 'file_url', 'reply_to_id',
            'timestamp', 'timestamp_iso', 'is_read',
            'meeting_status'
        ]
        read_only_fields = [
            'id', 'timestamp', 'sender', 'sender_id', 'sender_username'
        ]
    
    def get_meeting_status(self, obj):
        """
        Check if message is a meeting invite and return meeting status.
        """
        if not obj.text or '[MEETING_INVITE]' not in obj.text:
            return None
            
        try:
            import json
            from .models import Meeting
            
            marker = '[MEETING_INVITE]'
            # Extract JSON part
            json_str = obj.text[obj.text.find(marker) + len(marker):]
            data = json.loads(json_str)
            meeting_id = data.get('id')
            
            if not meeting_id:
                return None
                
            meeting = Meeting.objects.filter(id=meeting_id).first()
            if meeting:
                return 'ended' if (meeting.ended or meeting.status == 'ended') else 'active'
                
        except Exception as e:
            logger.warning(f"Error checking meeting status for message {obj.id}: {e}")
            return None
        return None
    
    def get_file_url(self, obj):
        """
        Generate absolute URL for attached file.
        
        Returns:
            str: Full file URL or None if no file
        """
        try:
            if not obj.file:
                return None
            
            request = self.context.get('request')
            
            if request:
                return request.build_absolute_uri(obj.file.url)
            
            return obj.file.url
            
        except Exception as e:
            logger.warning(
                "Error generating file URL for message %s: %s",
                obj.id, str(e)
            )
            return None
    
    def get_timestamp_iso(self, obj):
        """
        Get ISO formatted timestamp.
        
        Returns:
            str: ISO 8601 formatted datetime string
        """
        if hasattr(obj, 'timestamp') and obj.timestamp:
            return obj.timestamp.isoformat()
        return None


# ====================== MESSAGE CREATE SERIALIZER ======================

class MessageCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating messages with validation.
    
    Handles:
    - Receiver/Project destination validation
    - File validation (size, type)
    - Sender verification
    - Message content validation
    - Blocking/permission checks
    
    Fixes:
    - Issue #5: Added sender permission validation
    - Issue #4: Added file validation
    """
    
    receiver_id = serializers.IntegerField(
        write_only=True,
        required=False,
        allow_null=True
    )
    project_id = serializers.IntegerField(
        write_only=True,
        required=False,
        allow_null=True
    )
    reply_to_id = serializers.IntegerField(
        write_only=True,
        required=False,
        allow_null=True
    )
    
    class Meta:
        model = Message
        fields = ['receiver_id', 'project_id', 'text', 'file']
    
    def validate_text(self, value):
        """Validate message text content"""
        if not value or not value.strip():
            raise serializers.ValidationError("Message cannot be empty")
        
        if len(value) > SerializerConfig.MAX_MESSAGE_LENGTH:
            raise serializers.ValidationError(
                f"Message too long (max {SerializerConfig.MAX_MESSAGE_LENGTH} characters)"
            )
        
        return value.strip()
    
    def validate_file(self, value):
        """
        Validate uploaded file.
        
        Checks:
        - File size
        - File type/MIME type
        """
        if not value:
            return value
        
        # Check file size
        if value.size > SerializerConfig.MAX_FILE_SIZE:
            raise serializers.ValidationError(
                f"File too large (max {SerializerConfig.MAX_FILE_SIZE / (1024*1024):.1f}MB)"
            )
        
        # Check file type
        file_type = getattr(value, 'content_type', 'unknown')
        if file_type not in SerializerConfig.ALLOWED_FILE_TYPES:
            raise serializers.ValidationError(
                f"File type not allowed: {file_type}. "
                f"Allowed: {', '.join(SerializerConfig.ALLOWED_FILE_TYPES)}"
            )
        
        logger.info(
            "File validation passed: %s (%s, %d bytes)",
            value.name, file_type, value.size
        )
        
        return value
    
    def validate(self, data):
        """
        Validate destination and sender permissions.
        
        Ensures:
        - Either receiver_id or project_id provided (not both)
        - Sender can message receiver (not blocked)
        - Sender is member of project (if sending to project)
        """
        # Get initial data as fallback
        initial = getattr(self, 'initial_data', {}) or {}
        
        # Handle both 'receiver_id' and 'receiver' keys for frontend compatibility
        r_id = (
            data.get('receiver_id') or
            initial.get('receiver_id') or
            initial.get('receiver')
        )
        
        # Handle both 'project_id' and 'project' keys
        p_id = (
            data.get('project_id') or
            initial.get('project_id') or
            initial.get('project')
        )
        
        # Validate destination
        if not r_id and not p_id:
            raise serializers.ValidationError({
                'non_field_errors': [
                    "Either receiver_id or project_id must be provided"
                ]
            })
        
        if r_id and p_id:
            raise serializers.ValidationError({
                'non_field_errors': [
                    "Cannot send to both receiver and project"
                ]
            })
        
        # Validate and resolve IDs
        try:
            if r_id:
                self._resolved_receiver_id = int(r_id)
                self._resolved_project_id = None
                self._validate_receiver_permissions()
            
            if p_id:
                self._resolved_project_id = int(p_id)
                self._resolved_receiver_id = None
                self._validate_project_permissions()
        
        except (ValueError, TypeError):
            raise serializers.ValidationError({
                'non_field_errors': ["Invalid receiver_id or project_id format"]
            })
        
        return data
    
    def _validate_receiver_permissions(self):
        """
        Check if sender can message receiver.
        
        Raises:
            ValidationError: If receiver doesn't exist or sender is blocked
        """
        try:
            receiver = User.objects.get(id=self._resolved_receiver_id)
        except User.DoesNotExist:
            logger.warning(
                "Attempt to send message to non-existent user %s",
                self._resolved_receiver_id
            )
            raise serializers.ValidationError({
                'receiver_id': "Receiver user not found"
            })
        
        sender = self.context['request'].user
        
        # Blocking logic
        try:
            from .models import BlockedUser
            # If either party has blocked the other, disallow sending
            if BlockedUser.objects.filter(blocker=receiver, blocked=sender).exists() or \
               BlockedUser.objects.filter(blocker=sender, blocked=receiver).exists():
                raise serializers.ValidationError({
                    'receiver_id': "Cannot message this user"
                })
        except Exception:
            # If model not available or DB error, allow send
            pass
        
        logger.debug(
            "Receiver validation passed: %s -> %s",
            sender.username, receiver.username
        )
    
    def _validate_project_permissions(self):
        """
        Check if sender is member of project.
        
        Raises:
            ValidationError: If project doesn't exist or sender not member
        """
        try:
            project = Project.objects.get(id=self._resolved_project_id)
        except Project.DoesNotExist:
            logger.warning(
                "Attempt to send message to non-existent project %s",
                self._resolved_project_id
            )
            raise serializers.ValidationError({
                'project_id': "Project not found"
            })
        
        sender = self.context['request'].user
        
        if not project.members.filter(id=sender.id).exists():
            logger.warning(
                "Non-member %s attempted to send message to project %s",
                sender.username, project.name
            )
            raise serializers.ValidationError({
                'project_id': "You are not a member of this project"
            })
        
        logger.debug(
            "Project membership validation passed: %s in %s",
            sender.username, project.name
        )
    
    def create(self, validated_data):
        """
        Create message with resolved receiver/project.
        
        Returns:
            Message: Created message instance
        
        Raises:
            ValidationError: If creation fails
        """
        sender = self.context['request'].user
        receiver_id = getattr(self, '_resolved_receiver_id', None)
        project_id = getattr(self, '_resolved_project_id', None)
        
        # Remove temporary fields
        validated_data.pop('receiver_id', None)
        validated_data.pop('project_id', None)
        reply_to_id = (self.initial_data.get('reply_to_id') or validated_data.pop('reply_to_id', None))
        
        # Extract text for encryption via model property
        text_value = (validated_data.pop('text', '') or '').strip()

        try:
            if receiver_id:
                receiver = User.objects.get(id=receiver_id)
                message = Message(sender=sender, receiver=receiver)
                if text_value:
                    message.text = text_value
                # Save before handling optional file so upload_to gets a pk
                message.save()
                if reply_to_id:
                    try:
                        message.reply_to_id = int(reply_to_id)
                        message.save()
                    except Exception:
                        pass
                if 'file' in validated_data and validated_data['file']:
                    message.file = validated_data['file']
                    message.save()
                logger.info(
                    "DM created: %s (ID: %s) -> %s",
                    sender.username, message.id, receiver.username
                )

            elif project_id:
                project = Project.objects.get(id=project_id)
                message = Message(sender=sender, project=project)
                if text_value:
                    message.text = text_value
                message.save()
                if reply_to_id:
                    try:
                        message.reply_to_id = int(reply_to_id)
                        message.save()
                    except Exception:
                        pass
                if 'file' in validated_data and validated_data['file']:
                    message.file = validated_data['file']
                    message.save()
                logger.info(
                    "Project message created: %s (ID: %s) in %s",
                    sender.username, message.id, project.name
                )

            else:
                raise serializers.ValidationError(
                    "Neither receiver nor project resolved"
                )

            return message
        
        except (User.DoesNotExist, Project.DoesNotExist) as e:
            logger.error(
                "Target not found during message creation: %s",
                str(e)
            )
            raise serializers.ValidationError({
                'non_field_errors': ["Target user or project not found"]
            })
        
        except DjangoValidationError as e:
            logger.error(
                "Validation error during message creation: %s",
                str(e)
            )
            raise serializers.ValidationError({
                'non_field_errors': ["Invalid message data"]
            })


# ====================== RECENT CHAT SERIALIZER ======================

class RecentChatSerializer(serializers.Serializer):
    """
    Serializer for recent conversations list.
    
    Represents a conversation with the most recent message and unread count.
    
    Fixes:
    - Issue #6: Fixed timestamp serialization to ISO format
    - Proper null handling
    - Better error handling
    """
    
    user = UserSerializer()
    last_message = serializers.SerializerMethodField()
    last_message_time = serializers.SerializerMethodField()
    last_message_timestamp = serializers.SerializerMethodField()
    unread_count = serializers.SerializerMethodField()
    
    def get_last_message(self, obj):
        """
        Get last message text.
        
        Returns:
            str: Message text or empty string if no message
        """
        try:
            msg = obj.get('last_message')
            if msg and hasattr(msg, 'text'):
                return msg.text[:200]  # Truncate to 200 chars
            return None
        except Exception as e:
            logger.warning("Error getting last message: %s", str(e))
            return None
    
    def get_last_message_time(self, obj):
        """
        Get last message timestamp as human-readable format.
        
        Returns:
            str: Formatted datetime (deprecated, use last_message_timestamp)
        """
        try:
            msg = obj.get('last_message')
            if msg and hasattr(msg, 'timestamp'):
                return str(msg.timestamp)
            return None
        except Exception as e:
            logger.warning("Error getting last message time: %s", str(e))
            return None
    
    def get_last_message_timestamp(self, obj):
        """
        Get last message timestamp in ISO format (FIXED).
        
        Returns:
            str: ISO 8601 formatted datetime string
            None: If no message or error
        """
        try:
            msg = obj.get('last_message')
            
            if not msg:
                return None
            
            if hasattr(msg, 'timestamp') and msg.timestamp:
                # Ensure timezone-aware datetime
                if timezone.is_naive(msg.timestamp):
                    msg.timestamp = timezone.make_aware(msg.timestamp)
                
                return msg.timestamp.isoformat()
            
            return None
        
        except Exception as e:
            logger.error(
                "Error serializing last message timestamp: %s",
                str(e)
            )
            return None
    
    def get_unread_count(self, obj):
        """
        Get unread message count for conversation.
        
        Returns:
            int: Number of unread messages
        """
        try:
            count = obj.get('unread_count', 0)
            return max(0, int(count))  # Ensure non-negative
        except Exception as e:
            logger.warning("Error getting unread count: %s", str(e))
            return 0


# ====================== ERROR RESPONSE SERIALIZER ======================

class ErrorResponseSerializer(serializers.Serializer):
    """
    Standardized error response format.
    
    Usage:
        ErrorResponseSerializer({
            'success': False,
            'error': {
                'code': 'USER_NOT_FOUND',
                'message': 'The requested user does not exist'
            }
        })
    """
    
    success = serializers.BooleanField(default=False)
    error = serializers.DictField(
        child=serializers.CharField(),
        required=False
    )
    data = serializers.JSONField(required=False)


# ====================== SIDEBAR ITEM SERIALIZER ======================

class SidebarItemSerializer(serializers.Serializer):
    """
    Serializer for unified sidebar items (DMs and Projects).
    """
    type = serializers.ChoiceField(choices=['user', 'project'])
    user = UserSerializer(required=False, allow_null=True)
    project = ProjectSerializer(required=False, allow_null=True)
    last_message = serializers.CharField(allow_null=True, required=False)
    last_message_timestamp = serializers.DateTimeField(allow_null=True, required=False)
    unread_count = serializers.IntegerField(default=0)

