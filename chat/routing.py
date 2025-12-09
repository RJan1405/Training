# chat/routing.py
from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    # Direct Message chat
    # Example: ws/chat/user/2/
    re_path(r'ws/chat/user/(?P<user_id>\d+)/$', consumers.ChatConsumer.as_asgi()),

    # Project chat
    # Example: ws/chat/project/5/
    re_path(r'ws/chat/project/(?P<project_id>\d+)/$', consumers.ProjectChatConsumer.as_asgi()),

    # User notifications
    re_path(r'ws/notify/$', consumers.NotifyConsumer.as_asgi()),

    # Dedicated Meeting (Host Meeting)
    re_path(r'ws/meeting/(?P<meeting_id>[^/]+)/$', consumers.MeetingConsumer.as_asgi()),
]
