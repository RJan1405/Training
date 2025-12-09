# chat/consumers.py
# Rewritten, cleaned and upgraded for OPTION A (PURE WEBSOCKET)
import json
import logging
import base64
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.db import transaction
from .models import Message, Project

logger = logging.getLogger(__name__)


def _dm_group_name(a, b):
    """Deterministic DM group name for a pair of user ids"""
    low = min(int(a), int(b))
    high = max(int(a), int(b))
    return f"dm_{low}_{high}"


class ChatConsumer(AsyncWebsocketConsumer):
    """
    DM Chat consumer (ws/chat/user/<user_id>/)
    """

    async def connect(self):
        # partner id comes from URL: ws/chat/user/<user_id>/
        try:
            partner_id = int(self.scope['url_route']['kwargs'].get('user_id'))
        except Exception as e:
            logger.warning("connect: invalid partner id in URL: %s", e)
            return await self.close()

        self.user = self.scope.get('user')
        if not self.user or not getattr(self.user, 'is_authenticated', False):
            logger.info("connect: anonymous user attempted to open ws. Closing.")
            return await self.close()

        # Compute deterministic conversation group
        self.conversation_group = _dm_group_name(self.user.id, partner_id)
        self.partner_id = partner_id

        await self.channel_layer.group_add(self.conversation_group, self.channel_name)
        await self.accept()

        await self.set_user_online(True)

        try:
            await self.channel_layer.group_send(
                self.conversation_group,
                {
                    "type": "user_status",
                    "user_id": self.user.id,
                    "username": self.user.username,
                    "status": "online",
                },
            )
        except Exception:
            logger.exception("connect: failed to broadcast online status")

        logger.info("User %s connected to %s", self.user.username, self.conversation_group)

    async def disconnect(self, close_code):
        try:
            await self.set_user_online(False)
        except Exception:
            logger.exception("disconnect: set_user_online failed")

        try:
            await self.channel_layer.group_send(
                self.conversation_group,
                {
                    "type": "user_status",
                    "user_id": self.user.id,
                    "username": self.user.username,
                    "status": "offline",
                },
            )
        except Exception:
            logger.exception("disconnect: failed to broadcast offline status")

        try:
            await self.channel_layer.group_discard(self.conversation_group, self.channel_name)
        except Exception:
            logger.exception("disconnect: failed to discard group")

        logger.info("User %s disconnected from %s", getattr(self.user, "username", ""), getattr(self, "conversation_group", ""))

    async def receive(self, text_data=None, bytes_data=None):
        if not text_data:
            return

        try:
            data = json.loads(text_data)
        except Exception:
            logger.warning("receive: invalid json")
            return

        message_type = data.get('type')

        try:
            if message_type == 'message':
                await self.handle_message(data)
            elif message_type == 'read':
                await self.handle_read_receipt(data)
            elif message_type == 'typing':
                await self.handle_typing(data)
            elif message_type == 'rtc':
                await self.handle_rtc(data)
            else:
                logger.debug("receive: unknown message type: %s", message_type)
        except Exception:
            logger.exception("receive: error handling message")

    async def handle_message(self, data):
        """
        Handle 'message' payload from client:
        Expected: { type: 'message', receiver_id: <id>, text: '...', temp_id: '...' [, file_url, file_name, file_type] }
        Save to DB and broadcast a single event to the deterministic conversation group.
        """
        receiver_id = data.get('receiver_id')
        text = (data.get('text') or '').strip()
        file_url = data.get('file_url')
        file_name = data.get('file_name')
        file_type = data.get('file_type')
        reply_to_id = data.get('reply_to_id')
        temp_id = data.get('temp_id')

        if not receiver_id or text == '':
            logger.warning("handle_message: missing receiver or empty text")
            return

        # Save message (DB op) — uses model setter to encrypt
        msg = await self._save_message(receiver_id, text, file_url=file_url, file_name=file_name, file_type=file_type, reply_to_id=reply_to_id)

        if not msg:
            logger.error("handle_message: failed to save message to DB")
            return

        group = _dm_group_name(self.user.id, receiver_id)

        payload = {
            "type": "chat_message",  # handler name on consumer
            "id": msg.id,
            "temp_id": temp_id,  # echo back temp_id so frontend can reconcile
            "sender": self.user.id,
            "sender_id": self.user.id,
            "sender_username": self.user.username,
            "receiver": int(receiver_id),
            "receiver_id": int(receiver_id),
            "text": msg.text,  # decrypted via model property
            "file_url": msg.file.url if getattr(msg, 'file', None) else None,
            "timestamp": msg.timestamp.isoformat(),
            "reply_to_id": getattr(msg.reply_to, 'id', None),
            "is_read": bool(msg.is_read),
        }

        try:
            await self.channel_layer.group_send(group, payload)
            logger.debug("handle_message: broadcasted message %s to group %s with temp_id %s", msg.id, group, temp_id)
        except Exception:
            logger.exception("handle_message: failed to group_send")

    async def chat_message(self, event):
        """
        Receives chat_message events from the channel layer and forwards to the WebSocket client.
        """
        try:
            await self.send(text_data=json.dumps({
                "type": "message",
                "id": event.get("id"),
                "temp_id": event.get("temp_id"),
                "sender": event.get("sender"),
                "sender_id": event.get("sender_id"),
                "sender_username": event.get("sender_username"),
                "receiver": event.get("receiver"),
                "receiver_id": event.get("receiver_id"),
                "text": event.get("text"),
                "file_url": event.get("file_url"),
                "timestamp": event.get("timestamp"),
                "reply_to_id": event.get("reply_to_id"),
                "is_read": event.get("is_read", False),
            }))
        except Exception:
            logger.exception("chat_message: failed to send to websocket")

    async def handle_read_receipt(self, data):
        message_ids = data.get('message_ids') or []

        if not isinstance(message_ids, list) or not message_ids:
            return

        try:
            await self._mark_messages_read(message_ids)
        except Exception:
            logger.exception("handle_read_receipt: db update failed")

        try:
            await self.channel_layer.group_send(
                self.conversation_group,
                {
                    "type": "read_receipt",
                    "message_ids": message_ids,
                    "reader_id": self.user.id,
                },
            )
        except Exception:
            logger.exception("handle_read_receipt: group_send failed")

    async def read_receipt(self, event):
        try:
            await self.send(text_data=json.dumps({
                "type": "read_receipt",
                "message_ids": event.get("message_ids", []),
                "reader_id": event.get("reader_id"),
            }))
        except Exception:
            logger.exception("read_receipt: send failed")

    async def handle_typing(self, data):
        try:
            await self.channel_layer.group_send(
                self.conversation_group,
                {
                    "type": "typing_indicator",
                    "user_id": self.user.id,
                    "username": self.user.username,
                    "is_typing": bool(data.get("is_typing", True)),
                },
            )
        except Exception:
            logger.exception("handle_typing: failed to broadcast typing")

    async def typing_indicator(self, event):
        try:
            await self.send(text_data=json.dumps({
                "type": "typing",
                "user_id": event.get("user_id"),
                "username": event.get("username"),
                "is_typing": event.get("is_typing", True),
            }))
        except Exception:
            logger.exception("typing_indicator: send failed")

    async def user_status(self, event):
        try:
            await self.send(text_data=json.dumps({
                "type": "status",
                "user_id": event.get("user_id"),
                "username": event.get("username"),
                "status": event.get("status"),
            }))
        except Exception:
            logger.exception("user_status: send failed")

    async def handle_rtc(self, data):
        """
        Forward WebRTC signaling messages between DM participants.
        Expected: { type: 'rtc', action: 'offer|answer|candidate|end', sdp?, candidate?, call_type?, to }
        """
        action = (data.get('action') or '').strip()
        if action not in { 'offer', 'answer', 'candidate', 'end' }:
            logger.debug("handle_rtc: unknown action %s", action)
            return

        try:
            payload = {
                "type": "rtc_signal",
                "action": action,
                "from_id": self.user.id,
                "to_id": data.get('to'),
                "sdp": data.get('sdp'),
                "candidate": data.get('candidate'),
                "call_type": data.get('call_type'),
            }
            await self.channel_layer.group_send(self.conversation_group, payload)
            # Also notify the target user's notification channel so they see the call even if not in DM
            to_id = int(data.get('to') or 0)
            if to_id:
                await self.channel_layer.group_send(
                    f"user_notify_{to_id}",
                    {
                        "type": "rtc_signal_notify",
                        "action": action,
                        "from_id": self.user.id,
                        "to_id": to_id,
                        "sdp": data.get('sdp'),
                        "candidate": data.get('candidate'),
                        "call_type": data.get('call_type'),
                    },
                )
        except Exception:
            logger.exception("handle_rtc: group_send failed")

    async def rtc_signal(self, event):
        try:
            await self.send(text_data=json.dumps({
                "type": "rtc",
                "action": event.get("action"),
                "from_id": event.get("from_id"),
                "to_id": event.get("to_id"),
                "sdp": event.get("sdp"),
                "candidate": event.get("candidate"),
                "call_type": event.get("call_type"),
            }))
        except Exception:
            logger.exception("rtc_signal: send failed")

    # -----------------------
    # Database helpers
    # -----------------------

    @database_sync_to_async
    def _save_message(self, receiver_id, text, file_url=None, file_name=None, file_type=None, reply_to_id=None):
        """
        Save a Message instance. If file_url is a data URI, decode it and save.
        Uses the Message.text setter to encrypt.
        """
        try:
            receiver = User.objects.get(id=receiver_id)
        except User.DoesNotExist:
            logger.warning("_save_message: receiver %s does not exist", receiver_id)
            return None

        try:
            # Use setter so encryption happens in model
            message = Message(sender=self.user, receiver=receiver)
            message.text = text
            message.save()

            if reply_to_id:
                try:
                    message.reply_to_id = int(reply_to_id)
                    message.save()
                except Exception:
                    logger.exception("_save_message: setting reply_to failed")

            if file_url and file_name:
                try:
                    if isinstance(file_url, str) and file_url.startswith("data:"):
                        _, b64 = file_url.split(",", 1)
                        raw = base64.b64decode(b64)
                    else:
                        raw = file_url.encode() if isinstance(file_url, str) else file_url
                    message.file.save(file_name, ContentFile(raw))
                except Exception:
                    logger.exception("_save_message: saving file failed")
            return message

        except Exception:
            logger.exception("_save_message: creating message failed")
            return None

    @database_sync_to_async
    def _mark_messages_read(self, message_ids):
        """
        Concurrency-safe read marking: use atomic transaction and select_for_update
        """
        try:
            with transaction.atomic():
                (
                    Message.objects
                    .select_for_update()
                    .filter(id__in=message_ids, is_read=False)
                    .update(is_read=True)
                )
        except Exception:
            logger.exception("_mark_messages_read: DB update failed")

    @database_sync_to_async
    def set_user_online(self, is_online):
        """
        Best-effort: update the user's profile is_online field if available.
        """
        try:
            profile = getattr(self.user, "profile", None)
            if profile is not None:
                profile.is_online = bool(is_online)
                profile.save()
                return
        except Exception:
            logger.exception("set_user_online: profile update failed")

        try:
            from .models import UserProfile
        except Exception:
            UserProfile = None

        if UserProfile:
            try:
                profile, created = UserProfile.objects.get_or_create(user=self.user)
                profile.is_online = bool(is_online)
                profile.save()
            except Exception:
                logger.exception("set_user_online: UserProfile update failed")


# ----------------------------
# Project chat consumer (with temp_id support)
# ----------------------------
class ProjectChatConsumer(AsyncWebsocketConsumer):
    """
    Project chat consumer for project groups: ws/chat/project/<project_id>/
    Broadcasts messages to chat_project_<project_id>
    """

    async def connect(self):
        try:
            self.project_id = int(self.scope['url_route']['kwargs'].get('project_id'))
        except Exception:
            return await self.close()

        self.room_group_name = f"chat_project_{self.project_id}"
        self.user = self.scope.get('user')
        if not self.user or not getattr(self.user, 'is_authenticated', False):
            return await self.close()

        if not await self._is_member():
            logger.warning("connect: user %s is not a member of project %s", self.user.username, self.project_id)
            return await self.close()

        await self.channel_layer.group_add(self.room_group_name, self.channel_name)
        await self.accept()

        try:
            await self.set_user_online(True)
        except Exception:
            logger.exception("project connect: set_user_online failed")

        try:
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    "type": "user_status",
                    "user_id": self.user.id,
                    "username": self.user.username,
                    "status": "online",
                },
            )
        except Exception:
            logger.exception("project connect: failed to broadcast online status")

        logger.info("User %s connected to project %s", self.user.username, self.project_id)

    async def disconnect(self, close_code):
        try:
            await self.set_user_online(False)
        except Exception:
            logger.exception("project disconnect: set_user_online failed")

        try:
            await self.channel_layer.group_send(
            
                self.room_group_name,
                {
                    "type": "user_status",
                    "user_id": self.user.id,
                    "username": self.user.username,
                    "status": "offline",
                },
            )
        except Exception:
            logger.exception("project disconnect: failed to broadcast offline status")

        try:
            await self.channel_layer.group_discard(self.room_group_name, self.channel_name)
        except Exception:
            logger.exception("disconnect: failed to discard project group")
        logger.info("User %s disconnected from project %s", getattr(self.user, "username", ""), self.project_id)

    async def receive(self, text_data=None, bytes_data=None):
        if not text_data:
            return
        try:
            data = json.loads(text_data)
        except Exception:
            logger.warning("receive (project): invalid json")
            return

        t = data.get('type')
        try:
            if t == 'message':
                await self._handle_project_message(data)
            elif t == 'typing':
                await self._handle_project_typing(data)
            elif t == 'rtc':
                await self._handle_project_rtc(data)
            else:
                logger.debug("receive (project): unknown type %s", t)
        except Exception:
            logger.exception("receive (project): handler error")

    async def _handle_project_message(self, data):
        text = (data.get('text') or '').strip()
        if text == '':
            return

        file_url = data.get('file_url')
        file_name = data.get('file_name')
        temp_id = data.get('temp_id')
        reply_to_id = data.get('reply_to_id')

        msg = await self._save_project_message(text, file_url=file_url, file_name=file_name, reply_to_id=reply_to_id)
        if not msg:
            logger.error("_handle_project_message: failed to save")
            return

        payload = {
            "type": "project_message",
            "id": msg.id,
            "temp_id": temp_id,
            "sender": self.user.id,
            "sender_id": self.user.id,
            "sender_username": self.user.username,
            "project_id": self.project_id,
            "text": msg.text,
            "file_url": msg.file.url if getattr(msg, 'file', None) else None,
            "timestamp": msg.timestamp.isoformat(),
            "reply_to_id": getattr(msg.reply_to, 'id', None),
            "is_read": bool(msg.is_read),
        }

        try:
            await self.channel_layer.group_send(self.room_group_name, payload)
            logger.debug("_handle_project_message: broadcasted message %s to project %s with temp_id %s", msg.id, self.project_id, temp_id)
        except Exception:
            logger.exception("_handle_project_message: broadcast failed")

    async def project_message(self, event):
        try:
            await self.send(text_data=json.dumps({
                "type": "project_message",
                "id": event.get("id"),
                "temp_id": event.get("temp_id"),
                "sender": event.get("sender"),
                "sender_id": event.get("sender_id"),
                "sender_username": event.get("sender_username"),
                "project_id": event.get("project_id"),
                "text": event.get("text"),
                "file_url": event.get("file_url"),
                "timestamp": event.get("timestamp"),
                "reply_to_id": event.get("reply_to_id"),
                "is_read": event.get("is_read", False),
            }))
        except Exception:
            logger.exception("project_message: send failed")

    async def _handle_project_typing(self, data):
        try:
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    "type": "project_typing",
                    "user_id": self.user.id,
                    "username": self.user.username,
                    "is_typing": bool(data.get("is_typing", True)),
                },
            )
        except Exception:
            logger.exception("_handle_project_typing: failed")

    async def project_typing(self, event):
        try:
            await self.send(text_data=json.dumps({
                "type": "project_typing",
                "user_id": event.get("user_id"),
                "username": event.get("username"),
                "is_typing": event.get("is_typing", True),
            }))
        except Exception:
            logger.exception("project_typing: send failed")

    async def _handle_project_rtc(self, data):
        """
        Forward RTC signals for project mesh P2P.
        """
        try:
            payload = {
                "type": "project_rtc",
                "action": data.get("action"),
                "from_id": self.user.id,
                "to_id": data.get("to_id"),  # If targeted
                "sdp": data.get("sdp"),
                "candidate": data.get("candidate"),
            }
            await self.channel_layer.group_send(self.room_group_name, payload)
        except Exception:
            logger.exception("_handle_project_rtc: failed")

    async def project_rtc(self, event):
        try:
            await self.send(text_data=json.dumps({
                "type": "rtc",
                "action": event.get("action"),
                "from_id": event.get("from_id"),
                "to_id": event.get("to_id"),
                "sdp": event.get("sdp"),
                "candidate": event.get("candidate"),
            }))
        except Exception:
            logger.exception("project_rtc: send failed")

    async def user_status(self, event):
        try:
            await self.send(text_data=json.dumps({
                "type": "status",
                "user_id": event.get("user_id"),
                "username": event.get("username"),
                "status": event.get("status"),
            }))
        except Exception:
            logger.exception("project user_status: send failed")

    @database_sync_to_async
    def _is_member(self):
        try:
            project = Project.objects.get(id=self.project_id)
            return project.members.filter(id=self.user.id).exists()
        except Project.DoesNotExist:
            return False
        except Exception:
            logger.exception("_is_member: error")
            return False

    @database_sync_to_async
    def _save_project_message(self, text, file_url=None, file_name=None, reply_to_id=None):
        try:
            project = Project.objects.get(id=self.project_id)
        except Project.DoesNotExist:
            logger.warning("_save_project_message: project %s not found", self.project_id)
            return None

        try:
            # Use model setter to encrypt
            msg = Message(sender=self.user, project=project)
            msg.text = text
            msg.save()

            if reply_to_id:
                try:
                    msg.reply_to_id = int(reply_to_id)
                    msg.save()
                except Exception:
                    logger.exception("_save_project_message: setting reply_to failed")

            if file_url and file_name:
                try:
                    if isinstance(file_url, str) and file_url.startswith("data:"):
                        _, b64 = file_url.split(",", 1)
                        raw = base64.b64decode(b64)
                    else:
                        raw = file_url.encode() if isinstance(file_url, str) else file_url
                    msg.file.save(file_name, ContentFile(raw))
                except Exception:
                    logger.exception("_save_project_message: save file failed")

            return msg
        except Exception:
            logger.exception("_save_project_message: DB create failed")
            return None
    @database_sync_to_async
    def set_user_online(self, is_online):
        try:
            profile = getattr(self.user, "profile", None)
            if profile is not None:
                profile.is_online = bool(is_online)
                profile.save()
                return
        except Exception:
            logger.exception("project set_user_online: profile update failed")

        try:
            from .models import UserProfile
        except Exception:
            UserProfile = None

        if UserProfile:
            try:
                profile, created = UserProfile.objects.get_or_create(user=self.user)
                profile.is_online = bool(is_online)
                profile.save()
            except Exception:
                logger.exception("project set_user_online: UserProfile update failed")


# ----------------------------
# Notification consumer (user-scoped WebSocket)
# ----------------------------
class NotifyConsumer(AsyncWebsocketConsumer):
    """
    User notification channel. Clients connect at ws/notify/ once and
    stay subscribed to a per-user group (user_notify_<id>). Used to deliver
    RTC call invites and other alerts regardless of which chat is open.
    """

    async def connect(self):
        self.user = self.scope.get('user')
        if not self.user or not getattr(self.user, 'is_authenticated', False):
            return await self.close()

        self.group_name = f"user_notify_{self.user.id}"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        try:
            await self.channel_layer.group_discard(self.group_name, self.channel_name)
        except Exception:
            logger.exception("notify disconnect: group_discard failed")

    async def receive(self, text_data=None, bytes_data=None):
        if not text_data:
            return
        try:
            data = json.loads(text_data)
        except Exception:
            return

        if data.get('type') == 'rtc':
            await self._forward_rtc(data)

    async def _forward_rtc(self, data):
        """Allow clients to send RTC signals over notify channel as fallback."""
        action = (data.get('action') or '').strip()
        if action not in { 'offer', 'answer', 'candidate', 'end' }:
            return
        to_id = int(data.get('to') or 0)
        if not to_id:
            return
        try:
            await self.channel_layer.group_send(
                f"user_notify_{to_id}",
                {
                    "type": "rtc_signal_notify",
                    "action": action,
                    "from_id": self.user.id,
                    "to_id": to_id,
                    "sdp": data.get('sdp'),
                    "candidate": data.get('candidate'),
                    "call_type": data.get('call_type'),
                },
            )
        except Exception:
            logger.exception("notify _forward_rtc: group_send failed")


    async def rtc_signal_notify(self, event):
        try:
            await self.send(text_data=json.dumps({
                "type": "rtc",
                "action": event.get("action"),
                "from_id": event.get("from_id"),
                "to_id": event.get("to_id"),
                "sdp": event.get("sdp"),
                "candidate": event.get("candidate"),
                "call_type": event.get("call_type"),
            }))
        except Exception:
            logger.exception("notify rtc_signal_notify: send failed")


# ----------------------------
# Meeting Consumer (Dedicated Host Meeting)
# ----------------------------
class MeetingConsumer(AsyncWebsocketConsumer):
    """
    Consumer for dedicated meetings (Host Meeting feature).
    URL: ws/meeting/<meeting_id>/
    """
    async def connect(self):
        self.meeting_id = self.scope['url_route']['kwargs']['meeting_id']
        self.room_group_name = f'meeting_{self.meeting_id}'
        self.user = self.scope.get('user')

        if not self.user or not self.user.is_authenticated:
            await self.close()
            return

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()

        # Notify others that I have joined
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'user_joined',
                'user_id': self.user.id,
                'username': self.user.username
            }
        )

    async def disconnect(self, close_code):
        # Notify others that I have left
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'user_left',
                'user_id': self.user.id
            }
        )
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        data = json.loads(text_data)
        message_type = data.get('type')

        if message_type == 'signal':
            # Relay WebRTC signal to the targeting peer or broadcast
            # Expected payload: { 'type': 'signal', 'target': user_id, 'data': {...} }
            target_id = data.get('target')
            if target_id:
                # Optimized: ideally we'd send only to target's channel, but for simple Mesh 
                # we broadcast and let clients filter by 'target'
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'signal_message',
                        'sender_id': self.user.id,
                        'target_id': target_id,
                        'data': data.get('data')
                    }
                )

    # Handlers for group messages
    async def user_joined(self, event):
        # Don't send back to self
        if event['user_id'] == self.user.id:
            return
        await self.send(text_data=json.dumps({
            'type': 'user-joined',
            'user_id': event['user_id'],
            'username': event['username']
        }))

    async def user_left(self, event):
        if event['user_id'] == self.user.id:
            return
        await self.send(text_data=json.dumps({
            'type': 'user-left',
            'user_id': event['user_id']
        }))

    async def signal_message(self, event):
        # Only send if I am the target
        if event['target_id'] != self.user.id:
            return
        
        await self.send(text_data=json.dumps({
            'type': 'signal',
            'sender_id': event['sender_id'],
            'data': event['data']
        }))
