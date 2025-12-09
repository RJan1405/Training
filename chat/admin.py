from .models import Meeting, MeetingInvitation
from django.contrib import messages
from django.shortcuts import redirect, get_object_or_404
from django.urls import path, reverse
from django.contrib import admin
from django.utils.html import format_html
from .models import Project, Message, UserProfile


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):

    # WHAT YOU SEE IN LIST VIEW
    list_display = [
        'id',
        'get_message_type',
        'sender',
        'get_recipient',
        'preview',
        'timestamp',
        'is_read'
    ]

    list_filter = ['timestamp', 'is_read', 'project']
    search_fields = ['sender__username', 'receiver__username', 'project__name']
    date_hierarchy = 'timestamp'

    # ONLY READABLE FIELDS, NO encrypted_text
    readonly_fields = [
        'sender',
        'receiver',
        'project',
        'timestamp',
        'decrypted_text',
        'file',
    ]

    # NO encrypted_text in form— EVER!
    fieldsets = (
        ('Message Content', {
            'fields': (
                'decrypted_text',
                'file',
            )
        }),
        ('Meta Info', {
            'fields': (
                'sender',
                'receiver',
                'project',
                'timestamp',
                'is_read',
            )
        }),
    )

    # --- CUSTOM ADMIN DISPLAY HELPERS ---

    def decrypted_text(self, obj):
        """Show decrypted message text (from @property)."""
        return obj.text or ""
    decrypted_text.short_description = "Decrypted Text"

    def preview(self, obj):
        """Short trimmed preview."""
        text = obj.text or ""
        return (text[:60] + "...") if len(text) > 60 else text
    preview.short_description = "Preview"

    def get_message_type(self, obj):
        if obj.project:
            return format_html('<span style="color: green;">Project</span>')
        return format_html('<span style="color: blue;">DM</span>')
    get_message_type.short_description = 'Type'

    def get_recipient(self, obj):
        if obj.receiver:
            return obj.receiver.username
        return obj.project.name if obj.project else "—"
    get_recipient.short_description = 'Recipient'


# --- PROJECT ADMIN (unchanged) ---
@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ['name', 'member_count', 'created_at', 'created_by']
    search_fields = ['name', 'description']
    filter_horizontal = ['members']
    readonly_fields = ['created_at', 'updated_at', 'created_by']

    def member_count(self, obj):
        return obj.members.count()
    member_count.short_description = 'Members'

    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


# --- USER PROFILE ADMIN (unchanged) ---
@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'is_online_badge', 'last_seen']
    list_filter = ['is_online', 'last_seen']
    search_fields = ['user__username', 'user__email']
    readonly_fields = ['last_seen']

    def is_online_badge(self, obj):
        if obj.is_online:
            return format_html('<span style="color: green;">●</span> Online')
        return format_html('<span style="color: gray;">●</span> Offline')
    is_online_badge.short_description = 'Status'


# meetings/admin.py


# Optional: for broadcasting start/stop events to users (Django Channels)
try:
    from asgiref.sync import async_to_sync
    from channels.layers import get_channel_layer
    CHANNELS_AVAILABLE = True
except Exception:
    CHANNELS_AVAILABLE = False


class MeetingInvitationInline(admin.TabularInline):
    model = MeetingInvitation
    extra = 0
    readonly_fields = ('invited_at', 'responded_at', 'invite_link')
    fields = (
        'user',
        'accepted',
        'invited_by',
        'invited_at',
        'responded_at',
        'invite_link',
        'token',
    )
    show_change_link = True  # shows link to edit the invitation

    def invite_link(self, obj):
        # show a clickable join url (if you want)
        if not obj.pk:
            return "-"
        join_url = reverse('meeting:join', args=[obj.meeting_id])
        return format_html('<a href="{}" target="_blank">Open join link</a>', join_url)
    invite_link.short_description = "Join link"


@admin.register(Meeting)
class MeetingAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'host', 'status', 'scheduled_at',
                    'created_at', 'invited_count', 'started_button','ended')
    list_display_links = ('title',)  # click title to open meeting detail
    list_filter = ('status', 'host')
    search_fields = ('title', 'host__username', 'host__email')
    readonly_fields = ('created_at',)
    inlines = [MeetingInvitationInline]
    actions = ['start_meetings', 'end_meetings', 'export_invites_csv']

    def invited_count(self, obj):
        return obj.invitations.count()
    invited_count.short_description = "Invited"

    def started_button(self, obj):
        if obj.status == 'started':
            return "Started"
        if obj.status == 'ended' or obj.ended:
            return "Ended"
        url = reverse('admin:meetings_meeting_start', args=[obj.pk])
        return format_html('<a class="button" href="{}">Start</a>', url)
    started_button.short_description = "Start"

    # Admin actions
    def start_meetings(self, request, queryset):
        started = 0
        for meeting in queryset:
            if meeting.status != 'started':
                meeting.start()
                self._notify_meeting_started(meeting, request)
                started += 1
        messages.success(request, f"{started} meeting(s) started.")
    start_meetings.short_description = "Start selected meetings"

    def end_meetings(self, request, queryset):
        ended = 0
        for meeting in queryset:
            if meeting.status != 'ended':
                meeting.status = 'ended'
                meeting.ended = True
                meeting.save(update_fields=['status', 'ended'])
                # optional notify
                self._notify_meeting_ended(meeting, request)
                ended += 1
        messages.success(request, f"{ended} meeting(s) ended.")
    end_meetings.short_description = "End selected meetings"

    def export_invites_csv(self, request, queryset):
        # small convenience to export invites; optional
        import csv
        from django.http import HttpResponse
        meeting = queryset.first()
        if not meeting:
            messages.error(request, "Select a meeting.")
            return
        invites = meeting.invitations.select_related('user')
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="meeting_{meeting.id}_invites.csv"'
        writer = csv.writer(response)
        writer.writerow(['user_id', 'username', 'email',
                        'accepted', 'invited_at', 'responded_at', 'token'])
        for inv in invites:
            writer.writerow([inv.user.id, inv.user.username, inv.user.email,
                            inv.accepted, inv.invited_at, inv.responded_at, inv.token])
        return response
    export_invites_csv.short_description = "Export invites of selected meeting (CSV)"

    # Add custom admin URL(s) for start button
    def get_urls(self):
        urls = super().get_urls()
        custom = [
            path('<uuid:meeting_id>/start/', self.admin_site.admin_view(
                self.admin_start_meeting), name='meetings_meeting_start'),
            path('<uuid:meeting_id>/end/', self.admin_site.admin_view(
                self.admin_end_meeting), name='meetings_meeting_end'),
        ]
        return custom + urls

    def admin_start_meeting(self, request, meeting_id, *args, **kwargs):
        meeting = get_object_or_404(Meeting, pk=meeting_id)
        if meeting.status != 'started':
            meeting.start()
            self._notify_meeting_started(meeting, request)
            self.message_user(request, f"Meeting '{meeting.title}' started.")
        else:
            self.message_user(
                request, f"Meeting '{meeting.title}' is already started.", level=messages.WARNING)
        # redirect back to change page
        return redirect(reverse('admin:meetings_meeting_change', args=[meeting_id]))

    def admin_end_meeting(self, request, meeting_id, *args, **kwargs):
        meeting = get_object_or_404(Meeting, pk=meeting_id)
        meeting.status = 'ended'
        meeting.ended = True
        meeting.save(update_fields=['status', 'ended'])
        self._notify_meeting_ended(meeting, request)
        self.message_user(request, f"Meeting '{meeting.title}' ended.")
        return redirect(reverse('admin:meetings_meeting_change', args=[meeting_id]))

    # Notifications helper (uses Channels if available)
    def _notify_meeting_started(self, meeting, request=None):
        if not CHANNELS_AVAILABLE:
            return
        channel_layer = get_channel_layer()
        payload = {
            "event": "meeting_started",
            "meeting_id": str(meeting.id),
            "title": meeting.title,
            "join_url": request.build_absolute_uri(reverse('meeting:join', args=[meeting.id])) if request else ""
        }
        # notify room group and each invited user group
        async_to_sync(channel_layer.group_send)(f"meeting_{meeting.id}", {
            "type": "meeting.started", "payload": payload})
        for inv in meeting.invitations.select_related('user'):
            async_to_sync(channel_layer.group_send)(f"user_{inv.user.id}", {
                "type": "user.notify", "payload": payload})

    def _notify_meeting_ended(self, meeting, request=None):
        if not CHANNELS_AVAILABLE:
            return
        channel_layer = get_channel_layer()
        payload = {
            "event": "meeting_ended",
            "meeting_id": str(meeting.id),
            "title": meeting.title,
        }
        async_to_sync(channel_layer.group_send)(f"meeting_{meeting.id}", {
            "type": "meeting.ended", "payload": payload})
        for inv in meeting.invitations.select_related('user'):
            async_to_sync(channel_layer.group_send)(f"user_{inv.user.id}", {
                "type": "user.notify", "payload": payload})


@admin.register(MeetingInvitation)
class MeetingInvitationAdmin(admin.ModelAdmin):
    list_display = ('id', 'meeting', 'user', 'accepted',
                    'invited_at', 'responded_at')
    list_filter = ('accepted',)
    search_fields = ('user__username', 'user__email', 'meeting__title')
    raw_id_fields = ('user', 'meeting')
