# chat/views.py - FULLY FIXED VERSION

from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.shortcuts import render, redirect, get_object_or_404
from django.db.models import Q, F
from django.views.generic import TemplateView
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Message, Project
from .serializers import (
    MessageSerializer, UserSerializer, ProjectSerializer,
    MessageCreateSerializer, RecentChatSerializer, SidebarItemSerializer
)
from .forms import SignUpForm
from django.contrib.auth import login

# ==================== LOGIN VIEW ====================

class CustomLoginView(LoginView):
    """Custom login view"""
    template_name = 'login.html'
    redirect_authenticated_user = True

    def get_success_url(self):
        return '/chat/'

# ==================== SIGNUP VIEW ====================

def signup_view(request):
    """Signup view"""
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('chat_index')
    else:
        form = SignUpForm()
    return render(request, 'signup.html', {'form': form})


# ==================== AUTHENTICATION ====================

class IsAuthenticatedPermission(permissions.BasePermission):
    """Custom permission to check if user is authenticated"""
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated

# ==================== API VIEWS ====================

class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoints for users:
    - GET /api/users/ - List all users
    - GET /api/users/{id}/ - Get user detail
    - GET /api/users/search/?q=query - Search users
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticatedPermission]

    @action(detail=False, methods=['get'])
    def search(self, request):
        """Search users by username or email"""
        q = request.query_params.get('q', '')
        if len(q) < 1:
            return Response([], status=status.HTTP_400_BAD_REQUEST)
        users = User.objects.filter(
            Q(username__icontains=q) | Q(email__icontains=q)
        ).exclude(id=request.user.id)[:20]
        serializer = self.get_serializer(users, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def me(self, request):
        """Get current user info"""
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def block(self, request, pk=None):
        """Block a user (current user blocks target)."""
        try:
            target = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        if target.id == request.user.id:
            return Response({'error': 'Cannot block yourself'}, status=status.HTTP_400_BAD_REQUEST)

        from .models import BlockedUser
        obj, created = BlockedUser.objects.get_or_create(blocker=request.user, blocked=target)
        return Response({'blocked_user_id': target.id, 'created': created})

    @action(detail=True, methods=['post'])
    def unblock(self, request, pk=None):
        """Unblock a user."""
        try:
            target = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        from .models import BlockedUser
        BlockedUser.objects.filter(blocker=request.user, blocked=target).delete()
        return Response({'unblocked_user_id': target.id})

    @action(detail=False, methods=['post'], parser_classes=[MultiPartParser, FormParser])
    def upload_avatar(self, request):
        """Upload or update user avatar."""
        user = request.user
        if 'avatar' not in request.FILES:
            return Response({'error': 'No avatar file provided'}, status=status.HTTP_400_BAD_REQUEST)
        
        f = request.FILES['avatar']
        # Simple validation
        if f.size > 5 * 1024 * 1024:
             return Response({'error': 'File too large (max 5MB)'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            profile = user.profile
        except UserProfile.DoesNotExist:
            from .models import UserProfile
            profile = UserProfile.objects.create(user=user)

        profile.avatar = f
        profile.save()
        
        # Return the new avatar URL
        avatar_url = request.build_absolute_uri(profile.avatar.url)
        return Response({'avatar_url': avatar_url, 'message': 'Avatar updated successfully'})

    @action(detail=False, methods=['get'])
    def blocked(self, request):
        """List IDs of users blocked by current user."""
        from .models import BlockedUser
        ids = list(BlockedUser.objects.filter(blocker=request.user).values_list('blocked_id', flat=True))
        return Response({'blocked': ids})


class ProjectViewSet(viewsets.ModelViewSet):
    """
    API endpoints for projects:
    - GET /api/projects/ - List user's projects
    - POST /api/projects/ - Create project
    - GET /api/projects/{id}/ - Get project detail
    """
    serializer_class = ProjectSerializer
    permission_classes = [IsAuthenticatedPermission]
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    def get_queryset(self):
        """Only return projects the user is member of"""
        return Project.objects.filter(members=self.request.user)

    def perform_create(self, serializer):
        """Create project with current user as creator"""
        project = serializer.save(created_by=self.request.user)
        project.members.add(self.request.user)


class MessageViewSet(viewsets.ModelViewSet):
    """
    API endpoints for messages:
    - GET /api/messages/user/{id}/ - Get DM with user
    - GET /api/messages/project/{id}/ - Get project messages
    - POST /api/messages/send/ - Send message
    - GET /api/messages/recent_chats/ - Get recent conversations
    """
    serializer_class = MessageSerializer
    permission_classes = [IsAuthenticatedPermission]
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    @action(detail=False, methods=['get'], url_path='user/(?P<user_id>[^/.]+)')
    def get_user_messages(self, request, user_id=None):
        """Get DM conversation with specific user"""
        try:
            other_user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        messages = Message.objects.filter(
            Q(sender=request.user, receiver=other_user) |
            Q(sender=other_user, receiver=request.user)
        ).order_by('timestamp', 'id')

        # Mark as read
        Message.objects.filter(
            sender=other_user, receiver=request.user, is_read=False
        ).update(is_read=True)

        serializer = self.get_serializer(messages, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'], url_path='project/(?P<project_id>[^/.]+)')
    def get_project_messages(self, request, project_id=None):
        """Get messages for a project"""
        try:
            project = Project.objects.get(id=project_id)
        except Project.DoesNotExist:
            return Response({'error': 'Project not found'}, status=status.HTTP_404_NOT_FOUND)

        if request.user not in project.members.all():
            return Response({'error': 'Not a member of this project'}, status=status.HTTP_403_FORBIDDEN)

        messages = project.messages.all().order_by('timestamp', 'id')

        # Mark as read
        messages.filter(is_read=False).exclude(sender=request.user).update(is_read=True)

        serializer = self.get_serializer(messages, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    def send(self, request):
        """Send a message"""
        serializer = MessageCreateSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'])
    def recent_chats(self, request):
        """Get unified recent conversations (DMs and Projects)"""
        
        items = []

        # 1. PROCESS DIRECT MESSAGES
        recent_messages = Message.objects.filter(
            Q(sender=request.user) | Q(receiver=request.user)
        ).order_by('-timestamp', '-id')

        conversations_dict = {}
        for msg in recent_messages:
            if msg.project: 
                continue # Skip project messages here, handled separately
            
            other_user = msg.receiver if msg.sender == request.user else msg.sender
            if not other_user: 
                continue
            
            # Avoid showing blocked users if necessary, but skipping for now to match old logic
            
            if other_user.id not in conversations_dict:
                unread = Message.objects.filter(
                    sender=other_user, 
                    receiver=request.user, 
                    is_read=False
                ).count()
                
                conversations_dict[other_user.id] = {
                    'type': 'user',
                    'user': other_user,
                    'project': None,
                    # We pass the full user object to the serializer
                    'last_message': msg.text[:200] if msg.text else ('Attachment' if msg.file else ''),
                    'last_message_timestamp': msg.timestamp,
                    'unread_count': unread
                }
        items.extend(conversations_dict.values())

        # 2. PROCESS PROJECTS
        projects = Project.objects.filter(members=request.user)
        for proj in projects:
            last_msg = proj.messages.all().order_by('-timestamp', '-id').first()
            
            # Count unread messages in project (any message not by me that is unread)
            # Note: Is_read logic in projects might benefit from a separate ReadReceipt model 
            # effectively, currently Message.is_read is global. Assuming simplistic "unread" here.
            unread = proj.messages.filter(is_read=False).exclude(sender=request.user).count()
            
            ts = last_msg.timestamp if last_msg else proj.created_at
            txt = last_msg.text[:200] if last_msg and last_msg.text else ('Attachment' if last_msg and last_msg.file else '')
            if not last_msg: 
                txt = "Project Created"

            items.append({
                'type': 'project',
                'project': proj,
                'user': None,
                'last_message': txt,
                'last_message_timestamp': ts,
                'unread_count': unread
            })

        # 3. SORT & SERIALIZE
        def get_sort_key(item):
            t = item.get('last_message_timestamp')
            if not t: return timezone.now()
            return t

        items.sort(key=get_sort_key, reverse=True)

        serializer = SidebarItemSerializer(items, many=True, context={'request': request})
        return Response(serializer.data)

# ==================== PAGE VIEWS ====================

@login_required(login_url='login')
def chat_index(request):
    """Main chat interface"""
    user_projects = Project.objects.filter(members=request.user)
    context = {
        'user': request.user,
        'projects': user_projects
    }
    return render(request, 'chat/index.html', context)

@login_required(login_url='login')
def chat_window(request, chat_type, chat_id):
    """Chat window for specific DM or project"""
    context = {
        'chat_type': chat_type,
        'chat_id': chat_id,
        'current_user': request.user
    }
    return render(request, 'chat/chat_window.html', context)

# ==================== DEBUG SEND MESSAGE ENDPOINT ====================

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
@login_required(login_url='login')
def send_message_test(request):
    """Temporary CSRF-exempt endpoint to test message sending."""
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)

    text = request.POST.get("text", "").strip()
    receiver_id = request.POST.get("receiver")
    project_id = request.POST.get("project")

    if not text:
        return JsonResponse({"error": "text required"}, status=400)

    receiver = None
    project = None

    if receiver_id:
        try:
            receiver = User.objects.get(id=int(receiver_id))
        except:
            return JsonResponse({"error": "invalid receiver"}, status=400)

    if project_id:
        try:
            project = Project.objects.get(id=int(project_id))
        except:
            return JsonResponse({"error": "invalid project"}, status=400)

    msg = Message(sender=request.user, receiver=receiver, project=project)
    msg.text = text
    msg.save()

    return JsonResponse({
        "id": msg.id,
        "text": msg.text,
        "timestamp": msg.timestamp.isoformat() if hasattr(msg, "timestamp") else None,
        "sender": {
            "id": msg.sender.id,
            "username": msg.sender.username
        },
        "receiver": receiver.id if receiver else None,
        "project": project.id if project else None,
    }, status=201)
# ==================== MEETING VIEWS ====================

@login_required(login_url='login')
def meeting_room(request, meeting_id):
    """
    Render detailed meeting room page (separate from chat).
    """
    from .models import Meeting, MeetingInvitation
    
    try:
        meeting = Meeting.objects.get(id=meeting_id)
    except Meeting.DoesNotExist:
        return render(request, 'chat/index.html', {'error': 'Meeting not found'})
    
    # Ensure user has permission (host or invited)
    is_host = (meeting.host == request.user)
    is_invited = MeetingInvitation.objects.filter(meeting=meeting, user=request.user).exists()
    
    if not is_host and not is_invited:
        # Auto-invite if it's an "open" meeting or just let them in for now?
        # For this implementation, we'll auto-invite them if they have the link
        # This acts like a "Join" action
        MeetingInvitation.objects.create(
            meeting=meeting, 
            user=request.user, 
            invited_by=meeting.host, # Assumed host invited via link
            accepted=True
        )

    return render(request, 'chat/meeting_room.html', {
        'meeting': meeting,
        'user': request.user,
        'turn_config': settings.TURN_CONFIG if hasattr(settings, 'TURN_CONFIG') else []
    })

@csrf_exempt
@login_required
def create_meeting(request):
    """
    API to start a new dedicated meeting.
    POST /chat/api/meetings/create/
    Body: title, description, invites (JSON string of [{type: 'user'|'project', id: ...}])
    """
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
        
    from .models import Meeting, MeetingInvitation
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync
    import json
    
    title = request.POST.get("title", f"Meeting by {request.user.username}")
    description = request.POST.get("description", "")
    invites_json = request.POST.get("invites", "[]")
    
    try:
        invites = json.loads(invites_json)
    except:
        invites = []
    
    meeting = Meeting.objects.create(
        host=request.user,
        title=title,
        description=description,
        status='started',
        scheduled_at=timezone.now()
    )
    
    MeetingInvitation.objects.create(
        meeting=meeting,
        user=request.user,
        invited_by=request.user,
        accepted=True
    )
    
    channel_layer = get_channel_layer()
    
    for item in invites:
        target_type = item.get('type')
        target_id = item.get('id')
        
        if not target_id:
            continue
            
        invite_payload = json.dumps({
            "id": str(meeting.id),
            "title": meeting.title,
            "host": request.user.username
        })
        message_text = f"[MEETING_INVITE] {invite_payload}"
        
        try:
            if target_type == 'user':
                receiver = User.objects.get(id=target_id)
                msg = Message(sender=request.user, receiver=receiver)
                msg.text = message_text
                msg.save()
                
                MeetingInvitation.objects.get_or_create(
                    meeting=meeting,
                    user=receiver,
                    defaults={'invited_by': request.user}
                )
                
                # Broadcast DM
                group_name = f"chat_dm_{min(request.user.id, receiver.id)}_{max(request.user.id, receiver.id)}"
                async_to_sync(channel_layer.group_send)(group_name, {
                    "type": "chat_message",
                    "id": msg.id,
                    "sender": request.user.id,
                    "sender_id": request.user.id,
                    "sender_username": request.user.username,
                    "text": msg.text,
                    "timestamp": msg.timestamp.isoformat() if msg.timestamp else timezone.now().isoformat(),
                    "receiver": receiver.id
                })
                
            elif target_type == 'project':
                project = Project.objects.get(id=target_id)
                msg = Message(sender=request.user, project=project)
                msg.text = message_text
                msg.save()
                
                # Broadcast Project
                group_name = f"chat_project_{project.id}"
                async_to_sync(channel_layer.group_send)(group_name, {
                    "type": "project_message",
                    "id": msg.id,
                    "sender": request.user.id,
                    "sender_id": request.user.id,
                    "sender_username": request.user.username,
                    "project_id": project.id,
                    "text": msg.text,
                    "timestamp": msg.timestamp.isoformat() if msg.timestamp else timezone.now().isoformat()
                })
        except Exception as e:
            print(f"Error inviting {target_type} {target_id}: {e}")
            continue

    return JsonResponse({
        "status": "success",
        "meeting_id": str(meeting.id),
        "redirect_url": f"/chat/meeting/{meeting.id}/"
    })

@csrf_exempt
@login_required
def end_meeting(request, meeting_id):
    """
    API to end a meeting and notify participants.
    POST /chat/api/meetings/<id>/end/
    """
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
        
    from .models import Meeting
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync
    import json
    
    meet = get_object_or_404(Meeting, id=meeting_id, host=request.user)
    meet.status = 'ended'
    meet.ended = True
    meet.save()
    
    match_str = f'"{meet.id}"' 
    messages = Message.objects.filter(text__contains=match_str, sender=request.user)
    
    processed_targets = set()
    channel_layer = get_channel_layer()
    
    for m in messages:
        target_key = f"u_{m.receiver_id}" if m.receiver else f"p_{m.project_id}"
        if target_key in processed_targets:
            continue
            
        processed_targets.add(target_key)
        
        end_payload = json.dumps({"id": str(meet.id)})
        end_text = f"[MEETING_ENDED] {end_payload}"
        
        try:
            if m.receiver:
                msg = Message(sender=request.user, receiver=m.receiver)
                msg.text = end_text
                msg.save()
                
                group_name = f"chat_dm_{min(request.user.id, m.receiver.id)}_{max(request.user.id, m.receiver.id)}"
                async_to_sync(channel_layer.group_send)(group_name, {
                    "type": "chat_message",
                    "id": msg.id,
                    "sender": request.user.id,
                    "sender_id": request.user.id,
                    "sender_username": request.user.username,
                    "text": msg.text,
                    "timestamp": msg.timestamp.isoformat() if msg.timestamp else timezone.now().isoformat(),
                    "receiver": m.receiver.id
                })
                
            elif m.project:
                msg = Message(sender=request.user, project=m.project)
                msg.text = end_text
                msg.save()
                
                group_name = f"chat_project_{m.project.id}"
                async_to_sync(channel_layer.group_send)(group_name, {
                    "type": "project_message",
                    "id": msg.id,
                    "sender": request.user.id,
                    "sender_id": request.user.id,
                    "sender_username": request.user.username,
                    "project_id": m.project.id,
                    "text": msg.text,
                    "timestamp": msg.timestamp.isoformat() if msg.timestamp else timezone.now().isoformat()
                })
        except Exception as e:
            print(f"Error ending meeting notification: {e}")

    return JsonResponse({"status": "success"})
