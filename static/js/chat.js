/* ============================================================
   CHAT.JS - WITH FILES DISPLAY IN RIGHT SIDEBAR
   ============================================================
   Displays on RIGHT sidebar:
   - Chat avatar with initials (1-to-1)
   - Chat name (1-to-1)
   - Files shared count (1-to-1)
   - Total messages count (1-to-1)
   - ALL shared files list (1-to-1) ✨ NEW!
   - Project members (projects)
   ============================================================ */

const API_BASE = '/chat/api';
let currentChatType = null;
let currentChatId = null;
let ws = null;
let currentUserId = null;
let reconnectAttempts = 0;
const MAX_RECONNECT = 8;
let intersectionObserver = null;
let isUserNearBottomThreshold = 150;
let newMessageBadge = null;

// Presence control
let pendingOfflineTimer = null;
const OFFLINE_STABLE_MS = 2000;
let lastAppliedPresence = null;

// Message tracking
let addedMessageIds = new Set();
const localMessageMap = new Map();
const messageTextCache = new Map();

// Member sidebar tracking
let currentProjectMembers = new Map();
let currentProjectId = null;

// Chat metadata cache
let chatMetadata = new Map();

/* ============================================================
   INITIALIZE APP
   ============================================================ */

document.addEventListener('DOMContentLoaded', () => {
  console.log('🚀 Chat app initializing...');

  // Security Check: Warn if using HTTP on non-localhost
  if (location.protocol !== 'https:' && location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
    const banner = document.createElement('div');
    banner.style.background = '#ef4444';
    banner.style.color = 'white';
    banner.style.padding = '10px';
    banner.style.textAlign = 'center';
    banner.style.fontWeight = 'bold';
    banner.style.position = 'fixed';
    banner.style.top = '0';
    banner.style.left = '0';
    banner.style.right = '0';
    banner.style.zIndex = '99999';
    banner.innerHTML = `
      ⚠️ Video calls will NOT work on HTTP. 
      <a href="https://${location.hostname}:8001${location.pathname}" style="color: white; text-decoration: underline;">
        Click here to switch to HTTPS (Port 8001)
      </a>
    `;
    document.body.prepend(banner);
  }

  currentUserId = window.currentUserId ||
    parseInt(document.querySelector('[data-user-id]')?.getAttribute('data-user-id') || '0') ||
    parseInt(document.body.parentElement.getAttribute('data-user-id') || '0');

  console.log('✅ Current user ID:', currentUserId);

  if (!currentUserId || currentUserId === 0) {
    console.error('❌ User ID not found in page!');
  }

  loadUnifiedChats();
  setupEventListeners();

  try {
    hideRightSidebar();
    const mc = document.getElementById('main-container');
    if (mc) mc.classList.add('no-right-sidebar');
  } catch (e) { }

  connectNotifySocket();
});

/* ============================================================
   UNIFIED SIDEBAR (Recents + Projects)
   ============================================================ */

async function loadUnifiedChats() {
  try {
    const url = `${API_BASE}/messages/recent_chats/`;
    const res = await fetch(url, { headers: defaultHeaders() });
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const items = await res.json();

    // Cache metadata maps immediately
    items.forEach(item => {
      const type = item.type;
      const id = type === 'user' ? item.user.id : item.project.id;
      const key = `${type}_${id}`;
      if (!chatMetadata.has(key)) {
        chatMetadata.set(key, {
          filesCount: 0,
          lastActivity: item.last_message_timestamp,
          lastMessage: item.last_message,
          messageCount: 0,
          files: []
        });
      }
    });

    renderUnifiedChats(items);
  } catch (err) {
    console.error('❌ Error loading chats:', err);
  }
}

async function loadChatMetadata(type, id) {
  try {
    const key = `${type}_${id}`;
    // If we have files, assume we loaded full metadata
    if (chatMetadata.has(key) && chatMetadata.get(key).files.length > 0) return;

    let url = '';
    if (type === 'user') {
      url = `${API_BASE}/messages/user/${id}/`;
    } else {
      url = `${API_BASE}/messages/project/${id}/`;
    }

    const res = await fetch(url, { headers: defaultHeaders() });
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const messages = await res.json();

    let filesCount = 0;
    let lastActivityTime = null;
    let lastMessageText = '';
    const files = [];

    if (Array.isArray(messages)) {
      messages.forEach(msg => {
        if (msg.file_url) {
          filesCount++;
          files.push({
            name: msg.file_name || extractFileNameFromUrl(msg.file_url),
            url: msg.file_url,
            size: msg.file_size || 0,
            type: msg.file_type || '',
            timestamp: msg.timestamp
          });
        }
        if (msg.timestamp && (!lastActivityTime || new Date(msg.timestamp) > new Date(lastActivityTime))) {
          lastActivityTime = msg.timestamp;
          if (msg.text === '[PROJECT_MEETING_INVITE]') lastMessageText = '🎥 Meeting Started';
          else if (msg.text === '[PROJECT_MEETING_ENDED]') lastMessageText = '🏁 Meeting Ended';
          else lastMessageText = msg.text || (msg.file_url ? '📎 Attachment' : '');
        }
      });
    }

    chatMetadata.set(key, {
      filesCount,
      lastActivity: lastActivityTime,
      lastMessage: lastMessageText,
      messageCount: messages.length,
      files: files
    });

    // Update preview if element specifically exists for projects
    if (type === 'project') {
      const previewEl = document.getElementById(`project-preview-${id}`);
      if (previewEl && lastMessageText) previewEl.textContent = lastMessageText;
    }

  } catch (err) {
    console.error('❌ Error loading chat metadata:', err);
  }
}

function renderUnifiedChats(items) {
  const container = document.getElementById('all-chats-list');
  if (!container) return;

  container.innerHTML = '';
  if (!Array.isArray(items) || items.length === 0) {
    container.innerHTML = '<p class="empty-state">No conversations</p>';
    return;
  }

  items.forEach(item => {
    if (item.type === 'user' && item.user) {
      container.appendChild(createUnifiedUserItem(item));
    } else if (item.type === 'project' && item.project) {
      container.appendChild(createUnifiedProjectItem(item));
    }
  });
}

function createUnifiedUserItem(item) {
  const div = document.createElement('div');
  div.className = 'chat-item';
  div.tabIndex = 0;
  div.onclick = () => openChat('user', item.user.id);

  const avatar = document.createElement('div');
  avatar.className = 'avatar';
  const avatarUrl = item.user.profile?.avatar;
  if (avatarUrl) {
    // Determine full URL (if relative, prepend origin or rely on browser)
    // The backend serializer usually returns absolute or relative URL.
    avatar.style.backgroundImage = `url('${avatarUrl}')`;
    avatar.style.backgroundSize = 'cover';
    avatar.style.backgroundPosition = 'center';
    avatar.textContent = '';
  } else {
    avatar.textContent = (item.user.first_name?.[0] || item.user.username?.[0] || 'U').toUpperCase();
  }

  const info = document.createElement('div');
  info.className = 'chat-info';

  const name = document.createElement('div');
  name.className = 'chat-name';
  name.textContent = item.user.first_name ? `${item.user.first_name} ${item.user.last_name}` : item.user.username;

  const preview = document.createElement('div');
  preview.className = 'chat-preview';
  preview.textContent = item.last_message || '(No messages)';

  info.appendChild(name);
  info.appendChild(preview);
  div.appendChild(avatar);
  div.appendChild(info);

  if (item.unread_count > 0) {
    const badge = document.createElement('div');
    badge.className = 'unread-badge';
    badge.textContent = item.unread_count;
    badge.dataset.forUser = item.user.id;
    div.appendChild(badge);
  }

  return div;
}

function createUnifiedProjectItem(item) {
  const div = document.createElement('div');
  div.className = 'chat-item';
  div.onclick = () => openChat('project', item.project.id);

  const avatar = document.createElement('div');
  avatar.className = 'avatar project-avatar';
  avatar.textContent = (item.project.name?.[0] || 'P').toUpperCase();

  const info = document.createElement('div');
  info.className = 'chat-info';

  const name = document.createElement('div');
  name.className = 'chat-name';
  name.textContent = item.project.name;

  const preview = document.createElement('div');
  preview.className = 'chat-preview';
  preview.id = `project-preview-${item.project.id}`;
  preview.textContent = item.last_message || 'No messages';

  info.appendChild(name);
  info.appendChild(preview);
  div.appendChild(avatar);
  div.appendChild(info);

  if (item.unread_count > 0) {
    const badge = document.createElement('div');
    badge.className = 'unread-badge';
    badge.textContent = item.unread_count;
    div.appendChild(badge);
  }

  return div;
}

/* ============================================================
   OPEN CHAT - Main entry point
   ============================================================ */

function openChat(type, id) {
  console.log(`🔓 Opening ${type} chat with id ${id}`);
  closeComposeOverlay();
  currentChatType = type;
  currentChatId = Number(id);

  try {
    document.querySelectorAll('.chat-item').forEach(item => item.classList.remove('active'));
    if (window.event?.target) {
      const el = window.event.target.closest('.chat-item');
      if (el) el.classList.add('active');
    }
  } catch (e) {
    console.warn('Could not update active state:', e);
  }

  addedMessageIds.clear();
  localMessageMap.clear();

  if (type === 'project') {
    currentProjectId = id;
    loadProjectMembers(id);
  } else {
    currentProjectId = null;
  }

  loadChatWindow(type, id);
  connectWebSocket(type, id);
}

/* ============================================================
   LOAD CHAT WINDOW
   ============================================================ */

async function loadChatWindow(type, id) {
  const chatWindow = document.getElementById('chat-window');
  if (!chatWindow) return;

  try {
    let endpoint = '';
    let headerName = '';
    let isOnline = false;
    let avatarUrl = null;

    if (type === 'user') {
      endpoint = `${API_BASE}/messages/user/${id}/`;
      const user = await (await fetch(`${API_BASE}/users/${id}/`, { headers: defaultHeaders() })).json();
      headerName = user.first_name ? `${user.first_name} ${user.last_name}` : user.username;
      isOnline = !!(user.profile && user.profile.is_online);
      if (user.profile && user.profile.avatar) avatarUrl = user.profile.avatar;
    } else {
      endpoint = `${API_BASE}/messages/project/${id}/`;
      const project = await (await fetch(`${API_BASE}/projects/${id}/`, { headers: defaultHeaders() })).json();
      headerName = project.name;
      isOnline = true;
    }

    const res = await fetch(endpoint, { headers: defaultHeaders() });
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const messages = await res.json();

    const statusClass = isOnline ? 'online' : 'offline';
    const statusText = isOnline ? '● Online' : '● Offline';

    const mediaToggleBtn = '<button id="media-toggle-header-btn" title="Media" style="display:flex;align-items:center;justify-content:center;margin-left:6px;border:none;background:#e5e7eb;color:#374151;border-radius:8px;width:32px;height:32px;cursor:pointer;transition:all 0.2s"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg></button>';
    let callBtns = '';
    if (type === 'user') {
      callBtns = `
        <div class="call-buttons">
          <button id="voice-call-btn" class="call-btn" title="Voice Call" style="display:flex;align-items:center;justify-content:center;">
            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/></svg>
          </button>
          <button id="video-call-btn" class="call-btn" title="Video Call" style="display:flex;align-items:center;justify-content:center;">
             <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg>
          </button>
        </div>`;
    } else {
      callBtns = `
        <div class="call-buttons">
          <button id="project-meeting-btn" style="background:#2563eb; color:white; border:none; border-radius:8px; padding:8px 14px; font-size:13px; font-weight:600; cursor:pointer; display:flex; align-items:center; gap:8px; box-shadow:0 1px 3px rgba(0,0,0,0.1); transition: all 0.2s">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg>
            <span>Join Meeting</span>
          </button>
        </div>`;
    }

    let headerAvatar = '';
    if (avatarUrl) {
      headerAvatar = `<img src="${avatarUrl}" style="width:32px; height:32px; border-radius:50%; margin-right:8px; object-fit:cover;">`;
    } else {
      // Default avatar with initials
      const initials = (headerName.split(' ').map(n => n[0]).join('') || headerName[0] || '?').substring(0, 2).toUpperCase();
      headerAvatar = `
        <div style="width:32px; height:32px; border-radius:50%; margin-right:8px; background:linear-gradient(135deg, #2563eb 0%, #3b82f6 100%); color:white; display:flex; align-items:center; justify-content:center; font-weight:700; font-size:12px; border:1px solid #1e40af;">
          ${initials}
        </div>
      `;
    }

    chatWindow.innerHTML = `
      <div class="chat-header">
        <div class="chat-header-title" ${type === 'user' ? `onclick="openMemberProfile(${id})" style="cursor:pointer;"` : ''}>
          ${headerAvatar}
          <h3>${escapeHtml(headerName)}</h3>
          <span class="connection-status ${statusClass}">${statusText}</span>
          <button id="message-search-btn" style="display:flex;align-items:center;justify-content:center;margin-left:8px;border:none;background:#e5e7eb;color:#374151;border-radius:8px;width:32px;height:32px;cursor:pointer;transition:all 0.2s">
            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          </button>
          ${mediaToggleBtn}
          ${callBtns}
        </div>
      </div>
      <div class="messages-container" id="messages-container" tabindex="0" style="user-select: none"></div>
      <div id="reply-preview" class="reply-preview" style="display:none; padding:6px 10px; border-top:2px solid #d1d5db; border-bottom:2px solid #d1d5db; background:#f9fafb"></div>
      <div class="message-input-area">
        <div class="input-wrapper">
          <textarea id="message-input" class="message-input" placeholder="Type a message..." rows="1"></textarea>
          <button id="file-upload-btn" class="file-upload-btn" title="Upload file" style="padding:0;width:40px;display:flex;align-items:center;justify-content:center">
             <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>
          </button>
          <button id="send-btn" class="send-btn">
            <span>Send</span>
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-left:6px"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
          </button>
        </div>
      </div>
    `;

    const messagesContainer = document.getElementById('messages-container');

    if (Array.isArray(messages) && messages.length > 0) {
      const filtered = messages.filter((m) => {
        const sid = Number(m.sender_id);
        if (type === 'user') {
          if (sid !== Number(currentUserId) && isMessageAfterBlock(Number(id), m.timestamp)) return false;
          return true;
        }
        return !isMessageAfterBlock(sid, m.timestamp);
      });
      try { messages.forEach(m => { if (m && m.id != null) messageTextCache.set(Number(m.id), m.text || ''); }); } catch (e) { }
      filtered.forEach(msg => {
        addedMessageIds.add(msg.id);
        messagesContainer.appendChild(createMessageElement(msg));
      });
    }

    setupMessageInputHandlers(type, id);
    if (type === 'user' && isUserBlocked(Number(id))) {
      disableSendingForBlockedDM();
    }
    setupMessageSearchPanel();
    setupMediaToggle();
    setupCallButtons();
    setupReadReceiptObservers(messagesContainer);
    scrollToBottom();

    setTimeout(() => sendReadReceipts(true), 150);

    displayChatInfoOnSidebar(type, id, headerName);

  } catch (err) {
    console.error('❌ Error loading chat window:', err);
    chatWindow.innerHTML = `
      <div class="welcome-screen">
        <h2>Error</h2>
        <p>Failed to load chat: ${escapeHtml(err.message)}</p>
      </div>
    `;
  }
}

/* ============================================================
   DISPLAY CHAT INFO & FILES ON RIGHT SIDEBAR
   ============================================================ */

function displayChatInfoOnSidebar(type, id, chatName) {
  const chatInfoSection = document.querySelector('.chat-info-section');
  const filesSection = document.getElementById('files-section');
  const filesList = document.getElementById('files-list');
  const mediaSection = document.getElementById('media-section');
  const membersHeader = document.getElementById('members-header');
  const membersList = document.getElementById('members-list');
  const mainContainer = document.getElementById('main-container');

  if (!chatInfoSection) return;

  if (mediaSection) mediaSection.style.display = 'none';

  // Show/hide sections based on chat type
  if (type === 'project') {
    // For group chats, show members by default (hide files and chat info)
    showRightSidebar();
    if (mainContainer) mainContainer.classList.remove('no-right-sidebar');
    chatInfoSection.style.display = 'none';
    if (filesSection) filesSection.style.display = 'none';
    if (membersHeader) membersHeader.style.display = 'flex';
    if (membersList) membersList.style.display = '';
  } else {
    hideRightSidebar();
    if (mainContainer) mainContainer.classList.add('no-right-sidebar');
    chatInfoSection.style.display = 'none';
    if (filesSection) filesSection.style.display = 'none';
    if (membersHeader) membersHeader.style.display = 'none';
    if (membersList) membersList.style.display = 'none';
  }

  const avatar = document.getElementById('chat-info-avatar');
  const name = document.getElementById('chat-info-name');
  const filesCount = document.getElementById('chat-files-count');
  const messagesCount = document.getElementById('chat-messages-count');

  if (avatar && name && filesCount && messagesCount) {
    const initials = (chatName?.[0] || 'U').toUpperCase();
    avatar.textContent = initials;
    name.textContent = chatName;

    const metadataKey = `${type}_${id}`;
    const meta = chatMetadata.get(metadataKey) || {
      filesCount: 0,
      messageCount: 0,
      files: []
    };

    filesCount.textContent = `${meta.filesCount} file${meta.filesCount !== 1 ? 's' : ''}`;
    messagesCount.textContent = `${meta.messageCount} message${meta.messageCount !== 1 ? 's' : ''}`;

    if (type === 'project') {
      if (filesList) displaySharedFiles(meta.files || []);
    }

    console.log(`✅ Chat info displayed for ${chatName}:`, meta);
  }
}

/* ============================================================
   DISPLAY SHARED FILES IN RIGHT SIDEBAR
   ============================================================ */

function displaySharedFiles(files) {
  const filesList = document.getElementById('files-list');
  if (!filesList) return;

  filesList.innerHTML = '';

  if (!Array.isArray(files) || files.length === 0) {
    filesList.innerHTML = '<div class="files-empty" style="display:flex; flex-direction:column; align-items:center; opacity:0.6;"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:8px;"><path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 2H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"/></svg>No files shared</div>';
    return;
  }

  files.forEach(file => {
    const fileItem = createFileItem(file);
    filesList.appendChild(fileItem);
  });

  console.log(`✅ ${files.length} files displayed in sidebar`);
}

function setupMediaToggle() {
  const btn = document.getElementById('media-toggle-header-btn');
  if (!btn) return;
  btn.onclick = async () => {
    const mainContainer = document.getElementById('main-container');
    const chatInfoSection = document.getElementById('chat-info-section');
    const filesSection = document.getElementById('files-section');
    const membersHeader = document.getElementById('members-header');
    const membersList = document.getElementById('members-list');
    const mediaSection = document.getElementById('media-section');

    // For group chats (project), toggle between members and media
    if (currentChatType === 'project') {
      const isMembersShowing = membersHeader && membersHeader.style.display !== 'none';

      if (isMembersShowing) {
        // Currently showing members, switch to media
        if (membersHeader) membersHeader.style.display = 'none';
        if (membersList) membersList.style.display = 'none';
        if (mediaSection) mediaSection.style.display = 'flex';
        await renderMediaGallery(currentChatType, currentChatId);
      } else {
        // Currently showing media, switch back to members
        if (mediaSection) mediaSection.style.display = 'none';
        if (membersHeader) membersHeader.style.display = 'flex';
        if (membersList) membersList.style.display = '';
      }
      return;
    }

    // For 1-to-1 chats, toggle media view
    const isOpen = mediaSection && mediaSection.style.display !== 'none';
    if (isOpen) {
      if (mediaSection) mediaSection.style.display = 'none';
      if (currentChatType === 'project') {
        showRightSidebar();
        if (mainContainer) mainContainer.classList.remove('no-right-sidebar');
        if (chatInfoSection) chatInfoSection.style.display = 'none';
        if (filesSection) filesSection.style.display = 'none';
        if (membersHeader) membersHeader.style.display = 'flex';
        if (membersList) membersList.style.display = '';
      } else {
        hideRightSidebar();
        if (mainContainer) mainContainer.classList.add('no-right-sidebar');
        if (chatInfoSection) chatInfoSection.style.display = 'none';
        if (filesSection) filesSection.style.display = 'none';
        if (membersHeader) membersHeader.style.display = 'none';
        if (membersList) membersList.style.display = 'none';
      }
      return;
    }

    showRightSidebar();
    if (mainContainer) mainContainer.classList.remove('no-right-sidebar');
    if (chatInfoSection) chatInfoSection.style.display = 'none';
    if (filesSection) filesSection.style.display = 'none';
    if (membersHeader) membersHeader.style.display = 'none';
    if (membersList) membersList.style.display = 'none';
    if (mediaSection) mediaSection.style.display = 'flex';

    await renderMediaGallery(currentChatType, currentChatId);
  };
}

async function renderMediaGallery(type, id) {
  const grid = document.getElementById('media-grid');
  if (!grid) return;
  grid.innerHTML = '';

  if (!type || !id) {
    grid.innerHTML = '<div class="media-empty">No chat selected</div>';
    return;
  }

  let files = [];
  try {
    const key = `${type}_${id}`;
    const meta = chatMetadata.get(key);

    // Try to use cached files first for both user and project
    if (meta && Array.isArray(meta.files) && meta.files.length > 0) {
      files = meta.files;
    } else {
      // Fallback to fetch if not in cache (or empty cache but maybe server has new?)
      // Actually strictly relying on cache if populated is safer, but let's fetch if allow
      let url = '';
      if (type === 'user') {
        url = `${API_BASE}/messages/user/${id}/`;
      } else {
        url = `${API_BASE}/messages/project/${id}/`;
      }

      const res = await fetch(url, { headers: defaultHeaders() });
      const messages = res.ok ? await res.json() : [];
      files = messages.filter(m => m.file_url).map(m => ({
        name: m.file_name || extractFileNameFromUrl(m.file_url),
        url: m.file_url,
        size: m.file_size || 0,
        type: m.file_type || '', // Serializer doesn't provide this yet
        timestamp: m.timestamp
      }));
    }
  } catch (e) {
    grid.innerHTML = '<div class="media-empty">Failed to load media</div>';
    return;
  }

  if (!files.length) {
    grid.innerHTML = '<div class="media-empty">No media found</div>';
    return;
  }

  files.forEach(f => grid.appendChild(createMediaItem(f)));
}

function createMediaItem(file) {
  const div = document.createElement('div');
  div.className = 'media-item';
  const fileName = file.name || 'file.bin';
  const ext = (fileName.split('.').pop() || '').toLowerCase();

  if (isImageExt(ext)) {
    const img = document.createElement('img');
    img.src = file.url;
    div.appendChild(img);
  } else {
    const icon = document.createElement('div');
    icon.className = 'media-item-icon';
    icon.innerHTML = getFileIcon(ext, fileName);
    div.appendChild(icon);
  }

  div.title = fileName;
  div.onclick = () => {
    window.open(file.url, '_blank');
  };
  return div;
}

function isImageExt(ext) {
  return ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg'].includes(ext);
}
/* ============================================================
   CREATE FILE ITEM ELEMENT
   ============================================================ */

function createFileItem(file) {
  const div = document.createElement('div');
  div.className = 'file-item';
  div.title = file.name || file.file_name || 'File';

  const fileName = file.name || file.file_name || 'file.bin';
  const ext = (fileName.split('.').pop() || '').toLowerCase();
  const icon = getFileIcon(ext, fileName);
  const sizeText = formatFileSize(file.size || 0);

  const iconDiv = document.createElement('div');
  iconDiv.className = 'file-icon';
  iconDiv.innerHTML = icon;

  const infoDiv = document.createElement('div');
  infoDiv.className = 'file-info';

  const nameDiv = document.createElement('div');
  nameDiv.className = 'file-name';
  nameDiv.textContent = truncateFileName(fileName, 20);

  const sizeDiv = document.createElement('div');
  sizeDiv.className = 'file-size';
  sizeDiv.textContent = sizeText;

  infoDiv.appendChild(nameDiv);
  infoDiv.appendChild(sizeDiv);

  const downloadBtn = document.createElement('button');
  downloadBtn.className = 'file-download';
  downloadBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';
  downloadBtn.title = 'Download file';
  downloadBtn.onclick = (e) => {
    e.stopPropagation();
    if (file.url || file.file_url) {
      window.open(file.url || file.file_url, '_blank');
    }
  };

  div.onclick = () => {
    if (file.url || file.file_url) {
      window.open(file.url || file.file_url, '_blank');
    }
  };

  div.appendChild(iconDiv);
  div.appendChild(infoDiv);
  div.appendChild(downloadBtn);

  return div;
}

/* ============================================================
   GET FILE ICON BASED ON TYPE
   ============================================================ */

function getFileIcon(ext, fileName) {
  const s = (p) => `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${p}</svg>`;
  const map = {
    img: s('<rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/>'),
    doc: s('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/>'),
    zip: s('<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/>'),
    aud: s('<path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>'),
    vid: s('<polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/>'),
    code: s('<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>'),
    def: s('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>')
  };

  if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg'].includes(ext)) return map.img;
  if (['pdf', 'doc', 'docx', 'txt', 'rtf', 'xls', 'xlsx', 'csv', 'ppt', 'pptx'].includes(ext)) return map.doc;
  if (['zip', 'rar', '7z', 'tar'].includes(ext)) return map.zip;
  if (['mp3', 'wav', 'm4a', 'aac', 'flac'].includes(ext)) return map.aud;
  if (['mp4', 'webm', 'avi', 'mov', 'mkv', 'flv'].includes(ext)) return map.vid;
  if (['js', 'py', 'java', 'cpp', 'c', 'html', 'css', 'json'].includes(ext)) return map.code;
  return map.def;
}

/* ============================================================
   FORMAT FILE SIZE
   ============================================================ */

function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/* ============================================================
   TRUNCATE LONG FILE NAMES
   ============================================================ */

function truncateFileName(name, maxLength) {
  if (name.length <= maxLength) return name;
  const ext = name.split('.').pop();
  const nameWithoutExt = name.substring(0, name.length - ext.length - 1);
  const availableLength = maxLength - ext.length - 4;
  return nameWithoutExt.substring(0, availableLength) + '...' + '.' + ext;
}

/* ============================================================
   EXTRACT FILE NAME FROM URL
   ============================================================ */

function extractFileNameFromUrl(url) {
  if (!url) return 'file.bin';
  const parts = url.split('/');
  const fileName = parts[parts.length - 1];
  return fileName.split('?')[0] || 'file.bin';
}

function scrollToBottom() {
  const messagesContainer = document.getElementById('messages-container');
  if (messagesContainer) {
    // Immediate scroll
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
    // Delayed scroll to handle image/layout loading
    setTimeout(() => {
      messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }, 100);
    setTimeout(() => {
      messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }, 300);
  }
}

/* ============================================================
   MESSAGE ELEMENT CREATION
   ============================================================ */

function createMessageElement(msg) {
  const div = document.createElement('div');
  div.className = 'message';
  if (msg.id !== undefined) div.dataset.messageId = msg.id;
  if (msg.id !== undefined && isDeletedForMe(msg.id)) { div.style.display = 'none'; }
  if (msg.reply_to_id !== undefined) div.dataset.replyToId = msg.reply_to_id;

  const isOwn = (Number(msg.sender) === Number(currentUserId) ||
    Number(msg.sender_id) === Number(currentUserId) ||
    Number(msg.user_id) === Number(currentUserId) ||
    Number(msg.author) === Number(currentUserId));

  if (isOwn) div.classList.add('own-message');
  else div.classList.add('other-message');

  if (!msg.is_read) div.classList.add('not-read');

  if (!isOwn && msg.sender_username) {
    const senderEl = document.createElement('div');
    senderEl.className = 'message-sender';
    senderEl.textContent = msg.sender_username;
    div.appendChild(senderEl);
  }

  const content = document.createElement('div');
  content.className = 'message-body';

  const textEl = document.createElement('div');
  textEl.className = 'message-content';

  // Check for Meeting Invite
  if (msg.text === '[PROJECT_MEETING_INVITE]') {
    const inviteCard = document.createElement('div');
    inviteCard.className = 'meeting-invite-card';
    inviteCard.style.background = '#eff6ff';
    inviteCard.style.border = '1px solid #bfdbfe';
    inviteCard.style.borderRadius = '8px';
    inviteCard.style.padding = '12px';
    inviteCard.style.marginTop = '4px';
    inviteCard.style.display = 'flex';
    inviteCard.style.flexDirection = 'column';
    inviteCard.style.gap = '8px';

    const title = document.createElement('div');
    title.innerHTML = '<strong>🎥 Video Meeting Started</strong>';
    title.style.fontSize = '14px';
    title.style.color = '#1e3a8a';

    const joinBtn = document.createElement('button');
    joinBtn.textContent = 'Join Meeting';
    joinBtn.style.background = '#2563eb';
    joinBtn.style.color = 'white';
    joinBtn.style.border = 'none';
    joinBtn.style.padding = '8px 16px';
    joinBtn.style.borderRadius = '6px';
    joinBtn.style.fontWeight = '600';
    joinBtn.style.cursor = 'pointer';
    joinBtn.onclick = () => joinMeetingFromInvite();

    inviteCard.appendChild(title);
    inviteCard.appendChild(joinBtn);
    textEl.appendChild(inviteCard);
  } else if (msg.text === '[PROJECT_MEETING_ENDED]') {
    const endCard = document.createElement('div');
    endCard.style.padding = '8px 12px';
    endCard.style.background = '#f3f4f6';
    endCard.style.border = '1px solid #d1d5db';
    endCard.style.borderRadius = '8px';
    endCard.style.color = '#6b7280';
    endCard.style.fontSize = '13px';
    endCard.style.fontWeight = '500';
    endCard.style.display = 'flex';
    endCard.style.alignItems = 'center';
    endCard.style.gap = '8px';
    endCard.innerHTML = '<span>🏁</span> <span>Video meeting ended</span>';
    textEl.appendChild(endCard);

    // Disable the nearest previous invite card
    setTimeout(() => {
      if (!div.parentElement) return;
      let prev = div.previousElementSibling;
      while (prev) {
        const invite = prev.querySelector('.meeting-invite-card:not(.ended)');
        if (invite) {
          invite.classList.add('ended');
          const btn = invite.querySelector('button');
          if (btn) {
            btn.disabled = true;
            btn.textContent = 'Meeting Ended';
            btn.style.background = '#9ca3af';
            btn.style.cursor = 'not-allowed';
          }
          break; // Stop after disabling the most recent previous invite
        }
        prev = prev.previousElementSibling;
      }
    }, 100);
  } else {
    textEl.textContent = msg.text || '';
  }
  content.appendChild(textEl);

  const persistedReply = msg.id !== undefined ? getReplyForMessage(msg.id) : null;
  const effectiveReplyId = msg.reply_to_id ?? persistedReply?.reply_to_id;
  if (effectiveReplyId) {
    const refEl = document.querySelector(`.message[data-message-id="${effectiveReplyId}"] .message-content`);
    const quote = document.createElement('div');
    quote.className = 'message-quote';
    quote.style.borderLeft = '3px solid #bfdbfe';
    quote.style.background = '#538dff';
    quote.style.padding = '6px 8px';
    quote.style.margin = '6px 0 8px 0';
    quote.style.borderRadius = '6px';
    const fallbackText = persistedReply?.reply_text || messageTextCache.get(Number(effectiveReplyId)) || 'Quoted message';
    quote.textContent = refEl ? refEl.textContent : fallbackText;
    content.insertBefore(quote, textEl);
  }

  if (msg.file_url) {
    const fileAttachment = document.createElement('div');
    fileAttachment.className = 'file-attachment';
    const ext = (msg.file_url.split('.').pop() || '').toLowerCase();

    if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'].includes(ext)) {
      const img = document.createElement('img');
      img.src = msg.file_url;
      img.alt = 'attachment';
      img.loading = 'lazy';
      img.style.maxWidth = '100%';
      img.style.borderRadius = '6px';
      img.onclick = () => window.open(msg.file_url, '_blank');
      fileAttachment.appendChild(img);
    } else if (['mp4', 'webm', 'ogg', 'mov', 'avi'].includes(ext)) {
      const video = document.createElement('video');
      video.src = msg.file_url;
      video.controls = true;
      video.style.maxWidth = '100%';
      fileAttachment.appendChild(video);
    } else if (['mp3', 'wav', 'ogg', 'm4a'].includes(ext)) {
      const audio = document.createElement('audio');
      audio.src = msg.file_url;
      audio.controls = true;
      fileAttachment.appendChild(audio);
    } else {
      const link = document.createElement('a');
      link.href = msg.file_url;
      link.target = '_blank';
      link.textContent = `📥 ${msg.file_url.split('/').pop()}`;
      fileAttachment.appendChild(link);
    }
    content.appendChild(fileAttachment);
  }

  const meta = document.createElement('div');
  meta.className = 'message-meta';

  const time = document.createElement('div');
  time.className = 'message-time';
  time.textContent = new Date(msg.timestamp || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  meta.appendChild(time);

  if (isOwn) {
    const ticks = document.createElement('div');
    ticks.className = 'message-ticks';
    const t1 = document.createElement('span'); t1.className = 'tick tick-1'; t1.textContent = '✓';
    const t2 = document.createElement('span'); t2.className = 'tick tick-2'; t2.textContent = '✓';
    if (msg.is_read) {
      t1.classList.add('read');
      t2.classList.add('read');
    } else if (msg.is_delivered) {
      t1.classList.add('delivered');
    }
    ticks.appendChild(t1); ticks.appendChild(t2);
    meta.appendChild(ticks);
  }

  content.appendChild(meta);
  div.appendChild(content);

  setupMessageInteractions(div, msg);
  renderPersistedReactions(div, msg.id);

  return div;
}
function getList(key) { try { return JSON.parse(localStorage.getItem(key) || '[]'); } catch { return []; } }
function setList(key, arr) { localStorage.setItem(key, JSON.stringify(arr)); }
function toggleStar(id, el) { const key = 'starred_messages'; const list = getList(key); const idx = list.indexOf(id); if (idx >= 0) { list.splice(idx, 1); } else { list.push(id); addBadge(el, '★'); } setList(key, list); }
function togglePin(id, el) { const key = 'pinned_messages'; const list = getList(key); const idx = list.indexOf(id); if (idx >= 0) { list.splice(idx, 1); } else { list.push(id); addBadge(el, '📌'); } setList(key, list); }
function deleteForMe(id, el) { const key = 'deleted_for_me'; const list = getList(key); if (!list.includes(id)) list.push(id); setList(key, list); el.style.display = 'none'; }
function isDeletedForMe(id) { return getList('deleted_for_me').includes(id); }
function addBadge(el, sym) { const meta = el.querySelector('.message-meta'); if (!meta) return; const badge = document.createElement('span'); badge.textContent = sym; badge.style.marginLeft = '8px'; badge.style.fontSize = '12px'; meta.appendChild(badge); }
function toggleSelect(el) { const on = el.classList.toggle('selected'); el.style.outline = on ? '2px solid #2563eb' : 'none'; }
async function shareMessage(msg) { const text = msg.text || ''; const url = msg.file_url || ''; try { if (navigator.share) { await navigator.share({ text, url }); } else { await navigator.clipboard.writeText(text + (url ? `\n${url}` : '')); } } catch (e) { } }
let searchMatches = []; let searchIndex = -1; function setupMessageSearchPanel() { const btn = document.getElementById('message-search-btn'); if (!btn) return; btn.onclick = () => { openMessageSearchPanel(); }; }
function openMessageSearchPanel() { let panel = document.getElementById('message-search-panel'); if (panel) { panel.style.display = 'flex'; const inp = panel.querySelector('input'); if (inp) inp.focus(); return; } panel = document.createElement('div'); panel.id = 'message-search-panel'; panel.style.position = 'fixed'; panel.style.left = '12px'; panel.style.top = '12px'; panel.style.zIndex = '1001'; panel.style.background = '#111827'; panel.style.color = '#ffffff'; panel.style.border = '1px solid #374151'; panel.style.borderRadius = '8px'; panel.style.boxShadow = '0 8px 24px rgba(0,0,0,0.25)'; panel.style.padding = '8px'; panel.style.display = 'flex'; panel.style.gap = '6px'; const inp = document.createElement('input'); inp.type = 'text'; inp.placeholder = 'Search messages'; inp.style.padding = '6px 8px'; inp.style.border = '1px solid #374151'; inp.style.borderRadius = '6px'; inp.style.background = '#111827'; inp.style.color = '#ffffff'; inp.style.minWidth = '200px'; const prev = document.createElement('button'); prev.textContent = '◀'; prev.style.border = '1px solid #374151'; prev.style.borderRadius = '6px'; prev.style.background = '#1f2937'; prev.style.color = '#ffffff'; prev.style.padding = '6px 8px'; prev.style.cursor = 'pointer'; const next = document.createElement('button'); next.textContent = '▶'; next.style.border = '1px solid #374151'; next.style.borderRadius = '6px'; next.style.background = '#1f2937'; next.style.color = '#ffffff'; next.style.padding = '6px 8px'; next.style.cursor = 'pointer'; const close = document.createElement('button'); close.textContent = '✕'; close.style.border = '1px solid #374151'; close.style.borderRadius = '6px'; close.style.background = '#1f2937'; close.style.color = '#ffffff'; close.style.padding = '6px 8px'; close.style.cursor = 'pointer'; const clear = document.createElement('button'); clear.textContent = 'Clear'; clear.style.border = '1px solid #374151'; clear.style.borderRadius = '6px'; clear.style.background = '#1f2937'; clear.style.color = '#ffffff'; clear.style.padding = '6px 8px'; clear.style.cursor = 'pointer'; panel.appendChild(inp); panel.appendChild(prev); panel.appendChild(next); panel.appendChild(clear); panel.appendChild(close); document.body.appendChild(panel); const run = () => { const term = (inp.value || '').trim().toLowerCase(); const container = document.getElementById('messages-container'); if (!container) { return; } const items = container.querySelectorAll('.message'); searchMatches = []; searchIndex = -1; items.forEach(el => { el.classList.remove('search-match'); const body = el.querySelector('.message-content'); const quote = el.querySelector('.message-quote'); const txt = ((body?.textContent) || '') + ' ' + ((quote?.textContent) || ''); if (term && txt.toLowerCase().includes(term)) { el.classList.add('search-match'); searchMatches.push(el); } }); if (searchMatches.length) { searchIndex = 0; focusSearchMatch(searchIndex); } }; inp.oninput = run; prev.onclick = () => { if (!searchMatches.length) return; searchIndex = (searchIndex - 1 + searchMatches.length) % searchMatches.length; focusSearchMatch(searchIndex); }; next.onclick = () => { if (!searchMatches.length) return; searchIndex = (searchIndex + 1) % searchMatches.length; focusSearchMatch(searchIndex); }; clear.onclick = () => { inp.value = ''; run(); }; close.onclick = () => { panel.style.display = 'none'; }; inp.focus(); }
function focusSearchMatch(i) { const el = searchMatches[i]; if (!el) return; const container = document.getElementById('messages-container'); if (container) { const rect = el.getBoundingClientRect(); const cRect = container.getBoundingClientRect(); const offset = rect.top - cRect.top + container.scrollTop - 40; container.scrollTop = offset; } try { searchMatches.forEach(e => { e.style.outline = 'none'; e.style.background = ''; }); el.style.outline = '2px solid #f59e0b'; el.style.background = 'rgba(245,158,11,0.08)'; } catch (e) { } }
// Reactions persistence
function getReactionStore() { try { return JSON.parse(localStorage.getItem('reactions_store') || '{}'); } catch (e) { return {}; } }
function setReactionStore(store) { localStorage.setItem('reactions_store', JSON.stringify(store)); }
function renderPersistedReactions(el, id) { if (!id) return; const store = getReactionStore(); const arr = store[id] || []; let container = el.querySelector('.message-reactions'); if (!arr.length) { if (container) { try { container.remove(); } catch (e) { } } return; } if (!container) { container = document.createElement('div'); container.className = 'message-reactions'; container.style.marginTop = '6px'; container.style.display = 'inline-flex'; container.style.gap = '6px'; container.style.alignItems = 'center'; el.querySelector('.message-body').appendChild(container); } container.innerHTML = ''; arr.forEach(emoji => { const badge = document.createElement('button'); badge.type = 'button'; badge.textContent = emoji; badge.style.padding = '2px 6px'; badge.style.border = '1px solid #d1d5db'; badge.style.borderRadius = '12px'; badge.style.background = '#ffffff'; badge.style.cursor = 'pointer'; badge.onclick = () => { toggleReaction(id, emoji, el); }; container.appendChild(badge); }); }
function toggleReaction(id, emoji, el) { const store = getReactionStore(); const arr = store[id] || []; const idx = arr.indexOf(emoji); if (idx >= 0) arr.splice(idx, 1); else arr.push(emoji); store[id] = arr; setReactionStore(store); renderPersistedReactions(el, id); }
// Replies persistence
function getRepliesStore() { try { return JSON.parse(localStorage.getItem('replies_store') || '{}'); } catch (e) { return {}; } }
function setRepliesStore(store) { localStorage.setItem('replies_store', JSON.stringify(store)); }
function setReplyForMessage(id, reply_to_id, reply_text) { const store = getRepliesStore(); store[id] = { reply_to_id, reply_text }; setRepliesStore(store); }
function getReplyForMessage(id) { const store = getRepliesStore(); return store[id] || null; }

/* ============================================================
   MESSAGE INPUT HANDLERS
   ============================================================ */

function setupMessageInputHandlers(type, id) {
  const inputEl = document.getElementById('message-input');
  const sendBtn = document.getElementById('send-btn');
  const fileUploadBtn = document.getElementById('file-upload-btn');

  if (!inputEl || !sendBtn) return;

  sendBtn.onclick = () => sendMessageViaWebSocket(type, id);

  inputEl.onkeydown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessageViaWebSocket(type, id);
    }
  };

  inputEl.oninput = () => {
    inputEl.style.height = 'auto';
    inputEl.style.height = Math.min(inputEl.scrollHeight, 160) + 'px';
  };

  if (fileUploadBtn) {
    fileUploadBtn.onclick = () => {
      const input = document.createElement('input');
      input.type = 'file';
      input.onchange = (e) => uploadFileViaWebSocket(e, type, id);
      input.click();
    };
  }
}

let pendingReplyTo = null;
const REACTIONS = ['👍', '❤️', '😂', '🎉', '😮', '😢'];

function setupMessageInteractions(el, msg) {
  let pressTimer = null;
  let touchStartX = 0;
  let touchStartY = 0;
  let swiped = false;
  let swipeDir = null;
  let mouseDown = false;
  let mouseStartX = 0;
  let mouseStartY = 0;
  el.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    showActions();
  });

  const showReactions = () => {
    const bar = document.createElement('div');
    bar.className = 'reaction-bar';
    bar.style.position = 'absolute';
    bar.style.zIndex = '1000';
    bar.style.background = '#ffffff';
    bar.style.border = '1px solid #d1d5db';
    bar.style.boxShadow = '0 8px 20px rgba(0,0,0,0.12)';
    bar.style.borderRadius = '20px';
    bar.style.padding = '6px 8px';
    bar.style.display = 'flex';
    bar.style.gap = '6px';
    const rect = el.getBoundingClientRect();
    bar.style.left = `${rect.left + window.scrollX + 16}px`;
    bar.style.top = `${rect.top + window.scrollY - 40}px`;

    REACTIONS.forEach(r => {
      const b = document.createElement('button');
      b.type = 'button';
      b.textContent = r;
      b.style.fontSize = '16px';
      b.style.lineHeight = '16px';
      b.style.background = 'transparent';
      b.style.border = 'none';
      b.style.cursor = 'pointer';
      try {
        const store = getReactionStore();
        const arr = store[msg.id] || store[String(msg.id)] || [];
        if (arr.includes(r)) {
          b.style.background = '#fde68a';
          b.style.borderRadius = '50%';
        }
      } catch (e) { }
      b.onclick = () => {
        applyReaction(msg.id, r, el);
        bar.remove();
      };
      bar.appendChild(b);
    });

    document.body.appendChild(bar);
    const remove = () => { try { bar.remove(); } catch (e) { } };
    setTimeout(() => {
      document.addEventListener('click', remove, { once: true });
    }, 0);
  };

  const showActions = () => {
    const menu = document.createElement('div');
    menu.style.position = 'absolute';
    menu.style.background = '#111827';
    menu.style.color = '#ffffff';
    menu.style.border = '1px solid #374151';
    menu.style.borderRadius = '10px';
    menu.style.boxShadow = '0 10px 30px rgba(0,0,0,0.35)';
    menu.style.padding = '8px';
    menu.style.minWidth = '180px';
    menu.style.position = 'fixed';
    menu.style.zIndex = '1000';
    menu.style.visibility = 'hidden';

    const mkItem = (label) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.textContent = label;
      b.style.display = 'block';
      b.style.width = '100%';
      b.style.textAlign = 'left';
      b.style.padding = '8px 10px';
      b.style.margin = '2px 0';
      b.style.border = 'none';
      b.style.background = 'transparent';
      b.style.color = '#ffffff';
      b.style.cursor = 'pointer';
      b.onmouseenter = () => { b.style.background = '#1f2937'; };
      b.onmouseleave = () => { b.style.background = 'transparent'; };
      return b;
    };

    const replyItem = mkItem('Reply');
    replyItem.onclick = () => { startReplyTo(msg.id); close(); };
    const copyItem = mkItem('Copy');
    copyItem.onclick = async () => {
      try {
        const text = el.querySelector('.message-content')?.textContent || msg.text || '';
        await navigator.clipboard.writeText(text);
      } catch { }
      close();
    };
    const forwardItem = mkItem('Forward');
    forwardItem.onclick = () => { openForwardPicker(msg); close(); };
    const starItem = mkItem('Star');
    starItem.onclick = () => { toggleStar(msg.id, el); close(); };
    const pinItem = mkItem('Pin');
    pinItem.onclick = () => { togglePin(msg.id, el); close(); };
    const deleteItem = mkItem('Delete for me');
    deleteItem.onclick = () => { deleteForMe(msg.id, el); close(); };
    const selectItem = mkItem('Select');
    selectItem.onclick = () => { toggleSelect(el); };
    const shareItem = mkItem('Share');
    shareItem.onclick = async () => { await shareMessage(msg); close(); };

    // Context actions
    // Block/Unblock available in DM and project chats for messages from other users
    const isOwnMsg = el.classList.contains('own-message');
    const targetUserId = Number(msg.sender_id);
    if (!isOwnMsg && targetUserId && targetUserId !== Number(currentUserId)) {
      const blocked = isUserBlocked(targetUserId);
      const blockItem = mkItem(blocked ? 'Unblock user' : 'Block user');
      blockItem.style.color = blocked ? '#10b981' : '#ef4444';
      blockItem.onclick = async () => {
        try {
          if (blocked) {
            await unblockUser(targetUserId);
          } else {
            await blockUser(targetUserId);
          }
        } catch (e) { }
        close();
      };
      menu.appendChild(blockItem);
    }

    menu.appendChild(replyItem);
    menu.appendChild(copyItem);
    menu.appendChild(forwardItem);
    menu.appendChild(starItem);
    menu.appendChild(pinItem);
    menu.appendChild(deleteItem);
    menu.appendChild(selectItem);
    menu.appendChild(shareItem);

    const reactionsRow = document.createElement('div');
    reactionsRow.style.display = 'flex';
    reactionsRow.style.gap = '8px';
    reactionsRow.style.borderTop = '1px solid #374151';
    reactionsRow.style.marginTop = '6px';
    reactionsRow.style.paddingTop = '6px';
    REACTIONS.forEach(r => {
      const b = document.createElement('button');
      b.type = 'button';
      b.textContent = r;
      b.style.fontSize = '16px';
      b.style.background = 'transparent';
      b.style.border = 'none';
      b.style.cursor = 'pointer';
      b.onclick = () => { applyReaction(msg.id, r, el); close(); };
      reactionsRow.appendChild(b);
    });
    menu.appendChild(reactionsRow);

    const close = () => { try { menu.remove(); overlay.remove(); } catch (e) { } };
    const overlay = document.createElement('div');
    overlay.style.position = 'fixed';
    overlay.style.left = '0';
    overlay.style.top = '0';
    overlay.style.right = '0';
    overlay.style.bottom = '0';
    overlay.style.background = 'transparent';
    overlay.onclick = close;
    document.body.appendChild(overlay);
    document.body.appendChild(menu);

    try {
      const rect = el.getBoundingClientRect();
      const mw = menu.offsetWidth;
      const mh = menu.offsetHeight;
      const isOwn = el.classList.contains('own-message');
      let left = isOwn ? (rect.right - mw - 8) : (rect.left + 8);
      let top = rect.top - mh - 8;
      if (top < 8) top = rect.bottom + 8;
      const maxLeft = window.innerWidth - mw - 8;
      if (left < 8) left = 8;
      if (left > maxLeft) left = maxLeft;
      menu.style.left = `${Math.round(left)}px`;
      menu.style.top = `${Math.round(top)}px`;
    } catch (e) { }
    menu.style.visibility = 'visible';
  };

  const onLongPress = () => { showReactions(); };

  const startPress = () => {
    clearTimeout(pressTimer);
    pressTimer = setTimeout(onLongPress, 500);
  };
  const cancelPress = () => { clearTimeout(pressTimer); };

  // Mouse long-press, swipe and click
  el.addEventListener('mousedown', (e) => {
    if (e.button !== 0) return;
    mouseDown = true;
    mouseStartX = e.clientX;
    mouseStartY = e.clientY;
    startPress();
  });
  el.addEventListener('mousemove', (e) => {
    if (!mouseDown) return;
    const dx = e.clientX - mouseStartX;
    const dy = e.clientY - mouseStartY;
    if (Math.abs(dx) > 50 && Math.abs(dy) < 25) {
      swiped = true;
      swipeDir = dx > 0 ? 'right' : 'left';
      cancelPress();
    }
  });
  el.addEventListener('mouseup', (e) => {
    if (e.button !== 0) return;
    mouseDown = false;
    const wasSwiped = swiped; swiped = false;
    cancelPress();
    if (wasSwiped) {
      if (swipeDir === 'right') startReplyTo(msg.id);
      else showActions();
    }
  });
  el.addEventListener('mouseleave', () => { mouseDown = false; cancelPress(); });
  el.addEventListener('click', (e) => {
    if (e.button === 0 || e.button === 2) { // 0 is left click, 2 is right click
      e.preventDefault();
      showActions();
    }
  });

  el.addEventListener('touchstart', (e) => {
    if (e.touches && e.touches[0]) {
      touchStartX = e.touches[0].clientX;
      touchStartY = e.touches[0].clientY;
      swiped = false;
    }
    startPress();
  }, { passive: true });
  el.addEventListener('touchmove', (e) => {
    if (!e.touches || !e.touches[0]) return;
    const dx = e.touches[0].clientX - touchStartX;
    const dy = e.touches[0].clientY - touchStartY;
    if (Math.abs(dx) > 50 && Math.abs(dy) < 25) {
      swiped = true;
      swipeDir = dx > 0 ? 'right' : 'left';
      cancelPress();
    }
  }, { passive: true });
  el.addEventListener('touchend', () => {
    cancelPress();
    if (swiped) {
      if (swipeDir === 'right') startReplyTo(msg.id);
      else showActions();
    }
  });
}

function applyReaction(messageId, emoji, el) { toggleReaction(messageId, emoji, el); }

function startReplyTo(messageId) {
  pendingReplyTo = messageId;
  const preview = document.getElementById('reply-preview');
  const refEl = document.querySelector(`.message[data-message-id="${messageId}"] .message-content`);
  if (preview) {
    preview.style.display = 'flex';
    preview.style.alignItems = 'center';
    preview.style.gap = '8px';
    preview.innerHTML = '';
    const label = document.createElement('div');
    label.textContent = 'Replying to:';
    label.style.fontSize = '12px';
    label.style.color = '#6b7280';
    const text = document.createElement('div');
    text.textContent = refEl ? refEl.textContent : 'Quoted message';
    text.style.fontSize = '12px';
    text.style.color = '#374151';
    text.style.flex = '1';
    const cancel = document.createElement('button');
    cancel.type = 'button';
    cancel.textContent = 'Cancel';
    cancel.style.fontSize = '12px';
    cancel.style.border = '1px solid #d1d5db';
    cancel.style.borderRadius = '6px';
    cancel.style.padding = '4px 8px';
    cancel.onclick = () => { pendingReplyTo = null; preview.style.display = 'none'; };
    preview.appendChild(label);
    preview.appendChild(text);
    preview.appendChild(cancel);
  }
  const input = document.getElementById('message-input');
  if (input) input.focus();
}

function openForwardPicker(msg) {
  const modal = document.createElement('div');
  modal.style.position = 'fixed';
  modal.style.left = '50%';
  modal.style.top = '50%';
  modal.style.transform = 'translate(-50%, -50%)';
  modal.style.background = '#ffffff';
  modal.style.border = '2px solid #d1d5db';
  modal.style.boxShadow = '0 20px 40px rgba(0,0,0,0.2)';
  modal.style.borderRadius = '12px';
  modal.style.width = '360px';
  modal.style.maxWidth = '90vw';
  modal.style.maxHeight = '70vh';
  modal.style.overflow = 'auto';
  modal.style.padding = '12px';

  const title = document.createElement('h4');
  title.textContent = 'Forward to';
  title.style.margin = '0 0 8px 0';
  modal.appendChild(title);

  const list = document.createElement('div');
  list.style.display = 'flex';
  list.style.flexDirection = 'column';
  list.style.gap = '6px';
  modal.appendChild(list);

  const close = () => { try { overlay.remove(); modal.remove(); } catch (e) { } };
  const overlay = document.createElement('div');
  overlay.style.position = 'fixed';
  overlay.style.left = '0';
  overlay.style.top = '0';
  overlay.style.right = '0';
  overlay.style.bottom = '0';
  overlay.style.background = 'rgba(0,0,0,0.2)';
  overlay.onclick = close;
  document.body.appendChild(overlay);
  document.body.appendChild(modal);

  const addItem = (label, type, id) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = label;
    b.style.textAlign = 'left';
    b.style.padding = '8px 10px';
    b.style.border = '1px solid #d1d5db';
    b.style.borderRadius = '8px';
    b.style.background = '#f9fafb';
    b.onclick = async () => { await forwardMessageToTarget(type, id, msg); close(); };
    list.appendChild(b);
  };

  fetch(`${API_BASE}/messages/recent_chats/`, { headers: defaultHeaders() })
    .then(res => res.ok ? res.json() : [])
    .then(chats => {
      if (Array.isArray(chats)) chats.forEach(c => addItem(`User: ${c.user?.username || c.user?.email || c.user?.id}`, 'user', c.user?.id));
    })
    .catch(() => { });

  fetch(`${API_BASE}/projects/`, { headers: defaultHeaders() })
    .then(res => res.ok ? res.json() : [])
    .then(projects => {
      if (Array.isArray(projects)) projects.forEach(p => addItem(`Project: ${p.name}`, 'project', p.id));
    })
    .catch(() => { });
}

async function forwardMessageToTarget(type, id, msg) {
  const payload = {
    type: 'message',
    text: `Forwarded: ${msg.text || ''}`,
  };
  if (msg.file_url) payload.file_url = msg.file_url;
  if (type === 'user') payload.receiver_id = id; else payload.project_id = id;

  await sendMessageToTargetViaWebSocket(type, id, payload);
}

function sendMessageToTargetViaWebSocket(type, id, payload) {
  return new Promise((resolve) => {
    try {
      const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const url = `${protocol}//${location.host}/ws/chat/${type}/${id}/`;
      const sok = new WebSocket(url);
      sok.onopen = () => { try { sok.send(JSON.stringify(payload)); } catch (e) { } setTimeout(() => { try { sok.close(); } catch (e) { } resolve(); }, 150); };
      sok.onerror = () => { try { sok.close(); } catch (e) { } resolve(); };
      sok.onclose = () => resolve();
    } catch (e) { resolve(); }
  });
}

function getBlockedMap() {
  try {
    const raw = localStorage.getItem('blocked_users') || '{}';
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      const map = {};
      parsed.forEach((id) => { map[Number(id)] = map[Number(id)] || null; });
      return map;
    }
    if (parsed && typeof parsed === 'object') return parsed;
    return {};
  } catch (e) { return {}; }
}
function setBlockedMap(map) { localStorage.setItem('blocked_users', JSON.stringify(map)); }
function isUserBlocked(userId) { const m = getBlockedMap(); return Object.prototype.hasOwnProperty.call(m, String(userId)) || Object.prototype.hasOwnProperty.call(m, Number(userId)); }
function getBlockedAt(userId) { const m = getBlockedMap(); const v = m[String(userId)] ?? m[Number(userId)]; return v ? new Date(v) : null; }
function isMessageAfterBlock(userId, ts) { const at = getBlockedAt(userId); if (!at) return false; const d = new Date(ts || Date.now()); return d.getTime() > at.getTime(); }

async function blockUser(userId) {
  const url = `${API_BASE}/users/${userId}/block/`;
  try {
    const res = await fetch(url, { method: 'POST', headers: defaultHeaders() });
    if (!res.ok) throw new Error(`Status ${res.status}`);
  } catch (e) {
    // Fallback to local-only if API not available
  }
  const map = getBlockedMap();
  map[Number(userId)] = new Date().toISOString();
  setBlockedMap(map);
  alert('User blocked');
  // Disable sending in current DM if matches
  if (currentChatType === 'user' && Number(currentChatId) === Number(userId)) disableSendingForBlockedDM();
}

async function unblockUser(userId) {
  const url = `${API_BASE}/users/${userId}/unblock/`;
  try {
    const res = await fetch(url, { method: 'POST', headers: defaultHeaders() });
    if (!res.ok) throw new Error(`Status ${res.status}`);
  } catch (e) {
    // ignore
  }
  const map = getBlockedMap();
  delete map[Number(userId)];
  setBlockedMap(map);
  alert('User unblocked');
  if (currentChatType === 'user' && Number(currentChatId) === Number(userId)) enableSendingForDM();
}

function disableSendingForBlockedDM() {
  const inputEl = document.getElementById('message-input');
  const sendBtn = document.getElementById('send-btn');
  if (inputEl) { inputEl.disabled = true; inputEl.placeholder = 'You blocked this user'; }
  if (sendBtn) { sendBtn.disabled = true; sendBtn.textContent = 'Blocked'; }
}

function enableSendingForDM() {
  const inputEl = document.getElementById('message-input');
  const sendBtn = document.getElementById('send-btn');
  if (inputEl) { inputEl.disabled = false; inputEl.placeholder = 'Type a message...'; }
  if (sendBtn) { sendBtn.disabled = false; sendBtn.textContent = 'Send'; }
}

function sendMessageViaWebSocket(type, id) {
  const inputEl = document.getElementById('message-input');
  if (!inputEl) return;
  const text = inputEl.value.trim();
  if (!text) return;

  // Prevent sending to blocked users in DM
  if (type === 'user' && isUserBlocked(Number(id))) {
    alert('You blocked this user');
    disableSendingForBlockedDM();
    return;
  }

  if (!ws || ws.readyState !== WebSocket.OPEN) {
    console.error('❌ WebSocket not connected');
    connectWebSocket(type, id);
    return;
  }

  const temp_id = `temp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

  const localMsg = {
    id: temp_id,
    temp_id: temp_id,
    sender_id: currentUserId,
    sender_username: 'You',
    text: text,
    reply_to_id: pendingReplyTo || undefined,
    timestamp: new Date().toISOString(),
    is_read: false,
    is_delivered: false
  };

  const messagesContainer = document.getElementById('messages-container');
  const el = createMessageElement(localMsg);
  messagesContainer.appendChild(el);

  localMessageMap.set(temp_id, el);
  console.log('✅ Message appended locally with temp_id:', temp_id);

  if (pendingReplyTo) {
    try {
      const refEl = document.querySelector(`.message[data-message-id="${pendingReplyTo}"] .message-content`);
      setReplyForMessage(temp_id, pendingReplyTo, refEl ? refEl.textContent : 'Quoted message');
    } catch (e) { }
  }

  scrollToBottom();

  const payload = {
    type: 'message',
    text,
    temp_id: temp_id
  };
  if (pendingReplyTo) payload.reply_to_id = pendingReplyTo;

  if (type === 'user') payload.receiver_id = id;
  else payload.project_id = id;

  try {
    ws.send(JSON.stringify(payload));
    console.log('✅ Message sent via WebSocket');
  } catch (err) {
    console.error('❌ Failed to send message', err);
    localMessageMap.delete(temp_id);
  }

  inputEl.value = '';
  inputEl.style.height = 'auto';
  const preview = document.getElementById('reply-preview');
  if (preview) preview.style.display = 'none';
  pendingReplyTo = null;
}

function uploadFileViaWebSocket(e, type, id) {
  const file = e.target.files?.[0];
  if (!file) return;

  const maxSize = 10 * 1024 * 1024;
  if (file.size > maxSize) {
    alert('File too large! Max 10MB');
    return;
  }

  const reader = new FileReader();
  reader.onload = () => {
    const base64 = reader.result;
    const payload = {
      type: 'message',
      text: `[File: ${file.name}]`,
      file_url: base64,
      file_name: file.name,
      file_type: file.type
    };
    if (type === 'user') payload.receiver_id = id;
    else payload.project_id = id;

    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(payload));
    } else {
      alert('Network disconnected');
      connectWebSocket(type, id);
    }
  };
  reader.onerror = () => alert('Failed to read file');
  reader.readAsDataURL(file);
}

/* ============================================================
   PROJECT MEMBERS SIDEBAR (RIGHT SIDEBAR)
   ============================================================ */

async function loadProjectMembers(projectId) {
  try {
    const url = `${API_BASE}/projects/${projectId}/`;
    const res = await fetch(url, { headers: defaultHeaders() });
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const project = await res.json();

    currentProjectMembers.clear();
    if (Array.isArray(project.members)) {
      project.members.forEach(member => {
        currentProjectMembers.set(member.id, {
          id: member.id,
          username: member.username,
          first_name: member.first_name,
          last_name: member.last_name,

          is_online: member.profile?.is_online || false,
          avatar: member.profile?.avatar || null
        });
      });
    }

    renderProjectMembers();
    showRightSidebar();

  } catch (err) {
    console.error('❌ Error loading project members:', err);
    hideRightSidebar();
  }
}

function renderProjectMembers() {
  const membersList = document.getElementById('members-list');
  const membersCount = document.getElementById('members-count');

  if (!membersList) return;

  const members = Array.from(currentProjectMembers.values());

  members.sort((a, b) => {
    if (a.is_online !== b.is_online) {
      return a.is_online ? -1 : 1;
    }
    const nameA = a.first_name || a.username;
    const nameB = b.first_name || b.username;
    return nameA.localeCompare(nameB);
  });

  membersList.innerHTML = '';

  if (members.length === 0) {
    membersList.innerHTML = `
      <div class="members-empty">
        <div class="members-empty-icon">👥</div>
        <div class="members-empty-text">No members</div>
      </div>
    `;
    if (membersCount) membersCount.textContent = '0';
    return;
  }

  members.forEach(member => {
    const item = createMemberItem(member);
    membersList.appendChild(item);
  });

  if (membersCount) {
    membersCount.textContent = members.length;
  }
}

function createMemberItem(member) {
  const div = document.createElement('div');
  div.className = 'member-item';
  div.id = `member-${member.id}`;

  const avatar = document.createElement('div');
  avatar.className = 'member-avatar';
  const initials = member.first_name
    ? member.first_name[0].toUpperCase() + (member.last_name?.[0]?.toUpperCase() || '')
    : member.username[0].toUpperCase();

  if (member.avatar) {
    const img = document.createElement('img');
    img.src = member.avatar;
    img.style.width = '100%';
    img.style.height = '100%';
    img.style.objectFit = 'cover';
    img.style.borderRadius = '50%';
    avatar.appendChild(img);
  } else {
    avatar.textContent = initials;
  }

  const badge = document.createElement('div');
  badge.className = `status-badge ${member.is_online ? 'online' : ''}`;
  avatar.appendChild(badge);

  const info = document.createElement('div');
  info.className = 'member-info';

  const name = document.createElement('div');
  name.className = 'member-name';
  name.textContent = member.first_name
    ? `${member.first_name} ${member.last_name || ''}`.trim()
    : member.username;

  const status = document.createElement('div');
  status.className = `member-status ${member.is_online ? 'online' : 'offline'}`;
  status.textContent = member.is_online ? '● Online' : '● Offline';

  info.appendChild(name);
  info.appendChild(status);
  div.appendChild(avatar);
  div.appendChild(info);

  div.onclick = () => openMemberProfile(member.id);

  return div;
}

function showRightSidebar() {
  const sidebar = document.getElementById('right-sidebar');
  if (sidebar) sidebar.classList.remove('hidden');
}

function hideRightSidebar() {
  const sidebar = document.getElementById('right-sidebar');
  if (sidebar) sidebar.classList.add('hidden');
}

function updateMemberPresence(userId, status) {
  if (!userId || !currentProjectId) return;

  const member = currentProjectMembers.get(userId);
  if (!member) return;

  const isOnline = ('' + status).toLowerCase() === 'online';
  member.is_online = isOnline;

  const memberEl = document.getElementById(`member-${userId}`);
  if (memberEl) {
    const statusEl = memberEl.querySelector('.member-status');
    const badgeEl = memberEl.querySelector('.status-badge');

    if (statusEl) {
      statusEl.className = `member-status ${isOnline ? 'online' : 'offline'}`;
      statusEl.textContent = isOnline ? '● Online' : '● Offline';
    }

    if (badgeEl) {
      if (isOnline) {
        badgeEl.classList.add('online');
      } else {
        badgeEl.classList.remove('online');
      }
    }
  }

  renderProjectMembers();
}

async function openMemberProfile(userId) {
  const overlay = document.getElementById('profile-overlay');
  if (!overlay) return;
  overlay.classList.remove('hidden');

  const avatarEl = document.getElementById('profile-avatar');
  const nameEl = document.getElementById('profile-name');
  const usernameEl = document.getElementById('profile-username');
  const statusEl = document.getElementById('profile-status');
  const lastSeenEl = document.getElementById('profile-last-seen');
  const messageBtn = document.getElementById('profile-message');

  try {
    const res = await fetch(`${API_BASE}/users/${userId}/`, { headers: defaultHeaders() });
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const user = await res.json();

    const fullName = (user.first_name ? `${user.first_name} ${user.last_name || ''}`.trim() : user.username);
    const initials = (fullName?.[0] || 'U').toUpperCase();
    const isOnline = !!(user.profile && user.profile.is_online);
    const statusClass = isOnline ? 'online' : 'offline';
    const statusText = isOnline ? '● Online' : '● Offline';

    if (avatarEl) {
      avatarEl.innerHTML = '';
      if (user.profile && user.profile.avatar) {
        const img = document.createElement('img');
        img.src = user.profile.avatar;
        img.style.cursor = 'pointer';
        img.onclick = () => openAvatarPreview(user.profile.avatar);
        avatarEl.appendChild(img);
      } else {
        avatarEl.textContent = initials;
      }
    }
    if (nameEl) nameEl.textContent = fullName;
    if (usernameEl) usernameEl.textContent = `@${user.username}`;
    if (statusEl) { statusEl.className = `profile-status ${statusClass}`; statusEl.textContent = statusText; }
    if (lastSeenEl) {
      const ts = user.profile && user.profile.last_seen ? new Date(user.profile.last_seen) : null;
      lastSeenEl.textContent = ts ? `Last seen: ${ts.toLocaleString()}` : '';
    }
    if (messageBtn) {
      messageBtn.onclick = () => {
        openChatWithUser(user.id);
        closeProfileModal();
      };
    }
  } catch (e) {
    if (nameEl) nameEl.textContent = 'Unable to load profile';
    if (usernameEl) usernameEl.textContent = '';
  }

  const editAvatarBtn = document.getElementById('profile-edit-avatar-btn');
  const avatarInput = document.getElementById('avatar-input');

  // Show/Hide Edit Button
  if (editAvatarBtn) {
    if (Number(userId) === Number(currentUserId)) {
      editAvatarBtn.style.display = 'flex';
      editAvatarBtn.onclick = () => {
        if (avatarInput) avatarInput.click();
      };
      if (avatarInput) {
        avatarInput.onchange = async (e) => {
          if (e.target.files && e.target.files[0]) {
            await uploadAvatar(e.target.files[0]);
            // Refresh profile view
            openMemberProfile(currentUserId);
          }
        };
      }
    } else {
      editAvatarBtn.style.display = 'none';
    }
  }

  const closeBtn = document.getElementById('profile-close');
  if (closeBtn) closeBtn.onclick = closeProfileModal;
  overlay.onclick = (evt) => { if (evt.target === overlay) closeProfileModal(); };
}

function openAvatarPreview(url) {
  const overlay = document.getElementById('avatar-preview-overlay');
  const img = document.getElementById('avatar-preview-img');
  const closeBtn = document.getElementById('avatar-preview-close');

  if (overlay && img) {
    img.src = url;
    overlay.classList.remove('hidden');
    overlay.style.display = 'flex';

    if (closeBtn) closeBtn.onclick = closeAvatarPreview;
    overlay.onclick = (e) => {
      if (e.target === overlay) closeAvatarPreview();
    };
  }
}

function closeAvatarPreview() {
  const overlay = document.getElementById('avatar-preview-overlay');
  if (overlay) {
    overlay.classList.add('hidden');
    overlay.style.display = 'none';
  }
}

function closeProfileModal() {
  const overlay = document.getElementById('profile-overlay');
  if (overlay) overlay.classList.add('hidden');
}

/* ============================================================
   WEBSOCKET CONNECTION
   ============================================================ */

function connectWebSocket(type, id) {
  if (currentChatType !== type || currentChatId !== Number(id)) reconnectAttempts = 0;

  currentChatType = type;
  currentChatId = Number(id);

  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.close();
  }

  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${protocol}//${window.location.host}/ws/chat/${type}/${id}/`;
  console.log('🔌 Connecting to', url);

  try {
    ws = new WebSocket(url);
  } catch (err) {
    console.error('❌ WS constructor failed', err);
    scheduleReconnect(type, id);
    return;
  }

  ws.onopen = () => {
    console.log('✅ WebSocket connected');
    reconnectAttempts = 0;
    updateConnectionStatus(true);
  };

  ws.onmessage = (evt) => {
    try {
      const data = JSON.parse(evt.data);
      handleWebSocketMessage(data);
    } catch (err) {
      console.error('❌ Invalid WS message', err);
    }
  };

  ws.onerror = (err) => {
    console.error('❌ WebSocket error', err);
    updateConnectionStatus(false);
  };

  ws.onclose = (ev) => {
    console.warn('❌ WebSocket closed', ev);
    updateConnectionStatus(false);
    schedulePendingOffline();
    scheduleReconnect(type, id);
  };
}

function scheduleReconnect(type, id) {
  reconnectAttempts++;
  if (reconnectAttempts > MAX_RECONNECT) {
    console.warn('Max reconnect attempts reached');
    return;
  }
  const backoff = Math.min(1000 * (2 ** (reconnectAttempts - 1)), 30000);
  console.log(`⏳ Reconnect in ${backoff}ms (attempt ${reconnectAttempts})`);
  setTimeout(() => connectWebSocket(type, id), backoff);
}

/* ============================================================
   HANDLE WEBSOCKET MESSAGES
   ============================================================ */

function normalizeIncomingMessage(data) {
  if (!data) return data;

  return {
    id: data.id ?? data.message_id ?? data.pk ?? undefined,
    temp_id: data.temp_id ?? undefined,
    sender_id: data.sender_id ?? data.sender ?? data.from_id ?? undefined,
    sender: data.sender ?? data.sender_id ?? data.from_id ?? undefined,
    sender_username: data.sender_username ?? data.sender_name ?? data.username ?? undefined,
    receiver_id: data.receiver_id ?? data.to_id ?? undefined,
    project_id: data.project_id ?? data.project ?? undefined,
    text: data.text ?? data.message ?? '',
    file_url: data.file_url ?? data.file ?? undefined,
    reply_to_id: data.reply_to_id ?? data.reply_to ?? undefined,
    timestamp: data.timestamp ?? data.created_at ?? new Date().toISOString(),
    is_read: Boolean(data.is_read),
    is_delivered: Boolean(data.is_delivered)
  };
}

function handleWebSocketMessage(data) {
  if (!data || !data.type) return;
  const messagesContainer = document.getElementById('messages-container');

  if (data.type === 'message') {
    const msg = normalizeIncomingMessage(data);

    if (currentChatType !== 'user' || !currentChatId) {
      console.log('❌ Ignored DM message (no user chat open)', msg);
      return;
    }

    const senderId = Number(msg.sender_id);
    const receiverId = Number(msg.receiver_id);

    if (isMessageAfterBlock(senderId, msg.timestamp)) {
      console.log('❌ Ignored message from blocked user', senderId);
      return;
    }

    if (!(senderId === Number(currentChatId) || receiverId === Number(currentChatId))) {
      console.log('❌ Ignored DM message (not for current chat)', { currentChatType, currentChatId, msg });
      return;
    }

    if (!messagesContainer) return;

    if (msg.temp_id && localMessageMap.has(msg.temp_id)) {
      const el = localMessageMap.get(msg.temp_id);
      el.dataset.messageId = msg.id;
      const contentDiv = el.querySelector('.message-content');
      if (contentDiv) contentDiv.textContent = msg.text;
      const refIdStr = el.dataset.replyToId;
      if (refIdStr) {
        const refId = Number(refIdStr);
        const quoteEl = el.querySelector('.message-quote');
        setReplyForMessage(msg.id, refId, quoteEl ? quoteEl.textContent : '');
      }
      // migrate reactions from temp id to real id
      try {
        const store = getReactionStore();
        const tempArr = store[msg.temp_id] || store[String(msg.temp_id)] || null;
        if (tempArr && tempArr.length) {
          store[msg.id] = (store[msg.id] || []).concat(tempArr.filter((e) => !(store[msg.id] || []).includes(e)));
          delete store[msg.temp_id]; delete store[String(msg.temp_id)];
          setReactionStore(store);
          renderPersistedReactions(el, msg.id);
        }
      } catch (e) { }
      localMessageMap.delete(msg.temp_id);
      addedMessageIds.add(msg.id);
      console.log('✅ Message reconciled: temp_id', msg.temp_id, '→ real_id', msg.id);
      return;
    }

    if (addedMessageIds.has(msg.id)) {
      console.log('⚠️ Duplicate message prevented:', msg.id);
      return;
    }

    addedMessageIds.add(msg.id);

    const el = createMessageElement(msg);
    messagesContainer.appendChild(el);

    if (msg.reply_to_id) {
      try {
        const refEl = document.querySelector(`.message[data-message-id="${msg.reply_to_id}"] .message-content`);
        const quoteEl = el.querySelector('.message-quote');
        setReplyForMessage(msg.id, msg.reply_to_id, quoteEl ? quoteEl.textContent : (refEl ? refEl.textContent : 'Quoted message'));
      } catch (e) { }
    }

    if (isUserNearBottom(messagesContainer)) {
      scrollToBottom();
    } else {
      showNewMessageIndicator();
    }

    observeElementForRead(el);

    if (msg.file_url) {
      loadChatMetadata(currentChatType, currentChatId).then(() => {
        displayChatInfoOnSidebar(currentChatType, currentChatId,
          document.querySelector('.chat-header-title h3')?.textContent || 'Chat');
      });
    }

    loadRecentChats();
    return;
  }

  if (data.type === 'project_message') {
    const msg = normalizeIncomingMessage(data);
    const projId = Number(msg.project_id);

    if (currentChatType !== 'project' || Number(currentChatId) !== projId) {
      console.log('❌ Ignored project message (not current project)', { currentChatType, currentChatId, projId });
      return;
    }

    if (!messagesContainer) return;

    if (isMessageAfterBlock(Number(msg.sender_id), msg.timestamp)) {
      console.log('❌ Ignored project message from blocked user', msg.sender_id);
      return;
    }

    if (msg.temp_id && localMessageMap.has(msg.temp_id)) {
      const el = localMessageMap.get(msg.temp_id);
      el.dataset.messageId = msg.id;
      const contentDiv = el.querySelector('.message-content');
      if (contentDiv) contentDiv.textContent = msg.text;
      localMessageMap.delete(msg.temp_id);
      addedMessageIds.add(msg.id);
      console.log('✅ Project message reconciled: temp_id', msg.temp_id, '→ real_id', msg.id);
      return;
    }

    if (addedMessageIds.has(msg.id)) {
      console.log('⚠️ Duplicate project message prevented:', msg.id);
      return;
    }

    addedMessageIds.add(msg.id);

    const pel = createMessageElement(msg);
    messagesContainer.appendChild(pel);
    if (isUserNearBottom(messagesContainer)) scrollToBottom();
    observeElementForRead(pel);
    return;
  }

  if (data.type === 'status' || data.type === 'user_status') {
    if (data.status) updatePresenceFromServer(data.status);
    updateMemberPresence(data.user_id, data.status);
    return;
  }

  if (data.type === 'read_receipt') {
    const ids = Array.isArray(data.message_ids) ? data.message_ids : (data.message_ids ? [data.message_ids] : []);
    markMessagesReadInUI(ids, data.reader_id);
    updateSidebarUnreadCounts(ids);
    return;
  }

  if (data.type === 'rtc') {
    if (currentChatType === 'project') {
      handleProjectRTC(data);
    } else {
      handleRTCMessage(data);
    }
    return;
  }

  console.warn('Unhandled WS event type:', data.type);
}

/* ============================================================
   PRESENCE UPDATES
   ============================================================ */

function updatePresenceFromServer(status) {
  const normalized = ('' + status).toLowerCase() === 'online' ? 'online' : 'offline';
  const statusEl = document.querySelector('.connection-status');
  if (!statusEl) return;

  if (normalized === 'online') {
    if (pendingOfflineTimer) {
      clearTimeout(pendingOfflineTimer);
      pendingOfflineTimer = null;
    }
    if (lastAppliedPresence !== 'online') {
      statusEl.className = `connection-status online`;
      statusEl.textContent = `● Online`;
      lastAppliedPresence = 'online';
    }
    return;
  }

  if (normalized === 'offline') {
    if (lastAppliedPresence === 'offline') return;
    if (pendingOfflineTimer) clearTimeout(pendingOfflineTimer);

    pendingOfflineTimer = setTimeout(() => {
      const statusElem = document.querySelector('.connection-status');
      if (!statusElem) return;
      statusElem.className = `connection-status offline`;
      statusElem.textContent = `● Offline`;
      lastAppliedPresence = 'offline';
      pendingOfflineTimer = null;
    }, OFFLINE_STABLE_MS);

    return;
  }
}

function handleRTCMessage(data) {
  if (Number(data.from_id) === Number(currentUserId)) return;
  const action = data.action;
  if (action === 'offer') {
    rtcIncomingOffer = { sdp: data.sdp, call_type: data.call_type };
    rtcPeerToId = Number(data.from_id || 0);
    openCallOverlay(data.call_type === 'video' ? 'video' : 'audio', true);
    return;
  }
  if (action === 'answer') {
    if (rtcPeer && data.sdp) rtcPeer.setRemoteDescription(new RTCSessionDescription(data.sdp));
    return;
  }
  if (action === 'candidate') {
    try { if (rtcPeer && data.candidate) rtcPeer.addIceCandidate(new RTCIceCandidate(data.candidate)); } catch (e) { }
    return;
  }
  if (action === 'end') { endCall(); return; }
}

function schedulePendingOffline() {
  if (lastAppliedPresence === 'offline') return;

  if (pendingOfflineTimer) {
    clearTimeout(pendingOfflineTimer);
  }
  pendingOfflineTimer = setTimeout(() => {
    const statusElem = document.querySelector('.connection-status');
    if (!statusElem) return;
    statusElem.className = `connection-status offline`;
    statusElem.textContent = `● Offline`;
    lastAppliedPresence = 'offline';
    pendingOfflineTimer = null;
  }, OFFLINE_STABLE_MS);
}

/* ============================================================
   READ RECEIPTS
   ============================================================ */

function setupReadReceiptObservers(messagesContainer) {
  if (intersectionObserver) {
    try { intersectionObserver.disconnect(); } catch (e) { }
    intersectionObserver = null;
  }

  intersectionObserver = new IntersectionObserver((entries) => {
    const visibleUnreadIds = [];
    entries.forEach(entry => {
      if (!entry.isIntersecting) return;
      const el = entry.target;
      if (el && el.classList.contains('not-read')) {
        const id = parseInt(el.dataset.messageId);
        if (!Number.isNaN(id)) visibleUnreadIds.push(id);
      }
    });

    if (visibleUnreadIds.length > 0) {
      sendReadReceiptMessage(visibleUnreadIds);
      visibleUnreadIds.forEach(id => {
        const m = document.querySelector(`.message[data-message-id="${id}"]`);
        if (m) m.classList.remove('not-read');
      });
    }
  }, {
    root: messagesContainer,
    rootMargin: '0px',
    threshold: 0.6
  });

  const unreadEls = messagesContainer?.querySelectorAll('.message.not-read') || [];
  unreadEls.forEach(el => intersectionObserver.observe(el));
}

function observeElementForRead(el) {
  if (!intersectionObserver || !el) return;
  if (el.classList.contains('not-read')) {
    try { intersectionObserver.observe(el); } catch (e) { }
  }
}

function sendReadReceipts(forceSendAll = false) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  const container = document.getElementById('messages-container');
  if (!container) return;

  const notReadEls = Array.from(container.querySelectorAll('.message.not-read'));
  if (!notReadEls.length) return;

  if (!forceSendAll) {
    if (!isUserNearBottom(container)) return;
  }

  const ids = notReadEls.map(el => parseInt(el.dataset.messageId)).filter(Boolean);
  if (ids.length === 0) return;

  sendReadReceiptMessage(ids);
  ids.forEach(id => {
    const m = document.querySelector(`.message[data-message-id="${id}"]`);
    if (m) m.classList.remove('not-read');
  });
}

function sendReadReceiptMessage(messageIds) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  const payload = { type: 'read', message_ids: messageIds };
  try {
    ws.send(JSON.stringify(payload));
  } catch (err) {
    console.error('❌ Failed to send read receipt', err);
  }
}

/* ============================================================
   UI HELPERS
   ============================================================ */

function markMessagesReadInUI(messageIds = [], readerId = null) {
  messageIds.forEach(id => {
    const el = document.querySelector(`.message[data-message-id="${id}"]`);
    if (el) {
      el.classList.remove('not-read');
      const isOwn = el.classList.contains('own-message');
      if (isOwn) {
        const ticks = el.querySelectorAll('.tick');
        ticks.forEach(t => t.classList.add('read'));
      }
    }
  });
}

function updateSidebarUnreadCounts(messageIds = []) {
  loadRecentChats();
}

function isUserNearBottom(container) {
  if (!container) return true;
  const distanceFromBottom = container.scrollHeight - (container.scrollTop + container.clientHeight);
  return distanceFromBottom <= isUserNearBottomThreshold;
}

function showNewMessageIndicator() {
  if (!newMessageBadge) {
    newMessageBadge = document.createElement('button');
    newMessageBadge.className = 'new-message-badge';
    newMessageBadge.textContent = 'New messages';
    newMessageBadge.onclick = () => {
      const container = document.getElementById('messages-container');
      if (container) {
        container.scrollTop = container.scrollHeight;
      }
      newMessageBadge.remove();
      newMessageBadge = null;
      sendReadReceipts(true);
    };
    const chatWindow = document.getElementById('chat-window');
    if (chatWindow) chatWindow.appendChild(newMessageBadge);
  }
}

function updateConnectionStatus(isOnline) {
  const statusEl = document.querySelector('.connection-status');
  if (statusEl) {
    statusEl.className = `connection-status ${isOnline ? 'online' : 'offline'}`;
    statusEl.textContent = `● ${isOnline ? 'Online' : 'Offline'}`;
  }
}

/* ============================================================
   UTILITIES
   ============================================================ */

function defaultHeaders() {
  return {
    'Content-Type': 'application/json',
    'X-CSRFToken': getCSRFToken()
  };
}

function escapeHtml(unsafe) {
  if (unsafe === null || unsafe === undefined) return '';
  return String(unsafe)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function getCSRFToken() {
  return document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '';
}

function setupEventListeners() {
  document.addEventListener('keydown', (e) => {
    if ((e.key === 'k' || e.key === 'K') && (e.ctrlKey || e.metaKey)) {
      const input = document.getElementById('message-input');
      if (input) input.focus();
    }
    if (e.key === 'Escape') {
      closeComposeOverlay();
      closeProfileModal();
    }
  });

  window.addEventListener('focus', () => {
    sendReadReceipts(true);
  });

  document.addEventListener('contextmenu', (e) => {
    const container = document.getElementById('messages-container');
    if (container && container.contains(e.target)) e.preventDefault();
  }, true);

  document.addEventListener('selectstart', (e) => {
    const container = document.getElementById('messages-container');
    if (container && container.contains(e.target)) e.preventDefault();
  }, true);

  setupMediaToggle();
  setupNewChatButton();
  setupCallButtons();
  setupGroupCreationListeners();

  document.addEventListener('click', (e) => {
    const btn = e.target.closest('#new-chat-btn');
    if (btn) {
      e.preventDefault();
      const overlay = document.getElementById('compose-overlay');
      if (!overlay) return;
      const isOpen = (!overlay.classList.contains('hidden')) || (overlay.style.display && overlay.style.display !== 'none');
      if (isOpen) closeComposeOverlay(); else openComposeOverlay();
    }
  });

  console.log('✅ Event listeners setup complete');
}

function setupNewChatButton() {
  const btn = document.getElementById('new-chat-btn');
  if (!btn) return;
  const toggle = () => {
    const overlay = document.getElementById('compose-overlay');
    if (!overlay) return;
    const isOpen = (!overlay.classList.contains('hidden')) || (overlay.style.display && overlay.style.display !== 'none');
    if (isOpen) {
      closeComposeOverlay();
    } else {
      openComposeOverlay();
    }
  };
  btn.onclick = toggle;
  btn.addEventListener('click', toggle);
}

async function openComposeOverlay() {
  const overlay = document.getElementById('compose-overlay');
  const list = document.getElementById('compose-list');
  const inp = document.getElementById('compose-search-input');
  const modal = document.querySelector('#compose-overlay .compose-modal');
  const btn = document.getElementById('new-chat-btn');
  if (!overlay || !list) return;
  overlay.classList.remove('hidden');
  overlay.style.display = 'block';
  if (modal) { modal.style.visibility = 'visible'; modal.style.opacity = '1'; }
  try { document.body.style.overflow = 'hidden'; } catch (e) { }
  overlay.onclick = (e) => { if (e.target === overlay) closeComposeOverlay(); };
  inp.oninput = () => filterComposeList(inp.value.trim());
  const users = await fetchAllUsersForCompose();
  renderComposeList(users);

  if (modal && btn) {
    const rect = btn.getBoundingClientRect();
    const modalWidth = Math.min(380, Math.floor(window.innerWidth * 0.92));
    let left = rect.left;
    let top = rect.bottom + 8;
    if (left + modalWidth + 12 > window.innerWidth) left = window.innerWidth - modalWidth - 12;
    if (top + 420 > window.innerHeight) top = Math.max(12, window.innerHeight - 420);
    modal.style.left = `${left}px`;
    modal.style.top = `${top}px`;
  }
}

function closeComposeOverlay() {
  const overlay = document.getElementById('compose-overlay');
  if (overlay) { overlay.classList.add('hidden'); overlay.style.display = 'none'; }
  const modal = document.querySelector('#compose-overlay .compose-modal');
  if (modal) { modal.style.visibility = 'hidden'; modal.style.opacity = '0'; }
  try { document.body.style.overflow = ''; } catch (e) { }
  const list = document.getElementById('compose-list');
  const inp = document.getElementById('compose-search-input');
  if (list) list.innerHTML = '';
  if (inp) inp.value = '';
}

async function fetchAllUsersForCompose() {
  try {
    const res = await fetch(`${API_BASE}/users/`, { headers: defaultHeaders() });
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const users = await res.json();
    return users.filter(u => Number(u.id) !== Number(currentUserId));
  } catch (e) {
    return [];
  }
}

function renderComposeList(users) {
  const list = document.getElementById('compose-list');
  if (!list) return;
  list.innerHTML = '';
  if (!users.length) {
    list.innerHTML = '<div class="files-empty">No contacts</div>';
    return;
  }
  list.dataset.all = JSON.stringify(users);
  users.forEach(user => {
    const item = document.createElement('div');
    item.className = 'compose-item';
    const avatar = document.createElement('div');
    avatar.className = 'compose-avatar';
    if (user.profile && user.profile.avatar) {
      const img = document.createElement('img');
      img.src = user.profile.avatar;
      avatar.appendChild(img);
    } else {
      const initials = (user.first_name ? user.first_name[0] : user.username[0]).toUpperCase();
      avatar.textContent = initials;
    }
    const info = document.createElement('div');
    const name = document.createElement('div');
    name.className = 'compose-name';
    name.textContent = (user.first_name ? `${user.first_name} ${user.last_name || ''}`.trim() : user.username);
    const username = document.createElement('div');
    username.className = 'compose-username';
    username.textContent = `@${user.username}`;
    info.appendChild(name);
    info.appendChild(username);
    item.appendChild(avatar);
    item.appendChild(info);
    item.onclick = () => { openChatWithUser(user.id); closeComposeOverlay(); };
    list.appendChild(item);
  });
}

function filterComposeList(q) {
  const list = document.getElementById('compose-list');
  if (!list) return;
  let users = [];
  try { users = JSON.parse(list.dataset.all || '[]'); } catch (e) { users = []; }
  const normalized = (q || '').toLowerCase();
  const filtered = users.filter(u => {
    const full = (u.first_name ? `${u.first_name} ${u.last_name || ''}` : u.username).toLowerCase();
    return full.includes(normalized) || (u.username || '').toLowerCase().includes(normalized);
  });
  renderComposeList(filtered);
}

function openChatWithUser(userId) {
  openChat('user', userId);
  loadRecentChats();
}
let rtcPeer = null;
let rtcLocalStream = null;
let rtcCallType = 'audio';
let rtcIncomingOffer = null;
let rtcPeerToId = null;

function getRtcConfig() {
  const base = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };
  try {
    if (window.TURN_CONFIG && Array.isArray(window.TURN_CONFIG)) base.iceServers = base.iceServers.concat(window.TURN_CONFIG);
  } catch (e) { }
  return base;
}

function setupCallButtons() {
  const vBtn = document.getElementById('video-call-btn');
  const aBtn = document.getElementById('voice-call-btn');
  if (vBtn) vBtn.onclick = () => startOutgoingCall('video');
  if (aBtn) aBtn.onclick = () => startOutgoingCall('audio');

  const meetBtn = document.getElementById('project-meeting-btn');
  if (meetBtn) meetBtn.onclick = confirmHostMeeting;

  const endBtn = document.getElementById('call-end-btn');
  const acceptBtn = document.getElementById('call-accept-btn');
  const rejectBtn = document.getElementById('call-reject-btn');
  if (endBtn) endBtn.onclick = endCall;
  if (rejectBtn) rejectBtn.onclick = () => { sendRTC('end', {}); endCall(); };
  if (acceptBtn) acceptBtn.onclick = acceptIncomingCall;
  const overlay = document.getElementById('call-overlay');
  if (overlay) overlay.onclick = (e) => { if (e.target === overlay) endCall(); };
  const micBtn = document.getElementById('toggle-mic-btn');
  const camBtn = document.getElementById('toggle-cam-btn');
  if (micBtn) micBtn.onclick = () => { if (rtcLocalStream) rtcLocalStream.getAudioTracks().forEach(t => t.enabled = !t.enabled); };
  if (camBtn) camBtn.onclick = () => { if (rtcLocalStream) rtcLocalStream.getVideoTracks().forEach(t => t.enabled = !t.enabled); };

  // Project Meeting Controls
  const mCam = document.getElementById('meeting-cam-btn');
  const mMic = document.getElementById('meeting-mic-btn');
  const mShare = document.getElementById('meeting-share-btn');
  const mInvite = document.getElementById('meeting-invite-btn');

  if (mCam) mCam.onclick = toggleMeetingCam;
  if (mMic) mMic.onclick = toggleMeetingMic;
  if (mShare) mShare.onclick = toggleScreenShare;
  if (mInvite) mInvite.onclick = inviteToMeeting;

  const mExpand = document.getElementById('meeting-expand-btn');
  if (mExpand) mExpand.onclick = () => toggleMeetingSize();

  const mReact = document.getElementById('meeting-reaction-btn');
  const mHand = document.getElementById('meeting-hand-btn');

  if (mReact) {
    mReact.onclick = (e) => {
      e.stopPropagation();
      const popup = document.getElementById('reactions-popup');
      if (popup) popup.classList.toggle('hidden');
    };
    // Close popup when clicking outside
    document.addEventListener('click', (e) => {
      const popup = document.getElementById('reactions-popup');
      if (popup && !popup.contains(e.target) && e.target !== mReact) {
        popup.classList.add('hidden');
      }
    });
  }

  if (mHand) mHand.onclick = toggleRaiseHand;
}

/* ============================================================
   PROJECT MEETINGS (MESH P2P)
   ============================================================ */

let projectPeers = {}; // { userId: RTCPeerConnection }
let projectLocalStream = null;
let isScreenSharing = false;
let originalVideoTrack = null;
let isHandRaised = false;

async function openProjectMeeting() {
  if (currentChatType !== 'project' || !currentChatId) return;

  const overlay = document.getElementById('meeting-overlay');
  const container = document.getElementById('meeting-container');
  if (!overlay || !container) return;

  container.innerHTML = '';

  // Create grid layout
  container.style.display = 'grid';
  container.style.gridTemplateColumns = 'repeat(auto-fit, minmax(320px, 1fr))';
  container.style.gap = '10px';
  container.style.padding = '10px';
  container.style.alignContent = 'center';

  window.meetingStartTime = Date.now();

  // 1. Get Local Stream
  try {
    projectLocalStream = await navigator.mediaDevices.getUserMedia({
      audio: true,
      video: { width: { ideal: 640 }, height: { ideal: 360 } }
    });
  } catch (e) {
    alert("Could not access camera/mic: " + e.message);
    return;
  }

  // 2. Add Local Video to Grid
  addVideoTile(currentUserId, projectLocalStream, true);

  // 3. Show Overlay
  overlay.classList.remove('hidden');
  // Default to minimized ("small")
  overlay.classList.add('minimized');

  // 4. broadcast JOIN request to all group members
  sendProjectRTC({ action: 'join_request' });
}

window.closeMeetingOverlay = function () {
  const overlay = document.getElementById('meeting-overlay');
  const container = document.getElementById('meeting-container');
  if (overlay) overlay.classList.add('hidden');

  const wasActive = !!projectLocalStream;

  // Cleanup Local
  if (projectLocalStream) {
    projectLocalStream.getTracks().forEach(t => t.stop());
    projectLocalStream = null;
  }

  // Check if I was the last one (before clearing peers)
  const wasLast = Object.keys(projectPeers).length === 0;

  // Safety: We suppress the "Meeting Ended" message if the user wasn't actually active (no stream),
  // which prevents ghost/glitch endings.
  // We removed the duration check because if a user manually clicks End quickly, they expect it to end.
  console.log(`❌ closeMeetingOverlay checks: wasLast=${wasLast}, wasActive=${wasActive}`);

  if (wasLast && wasActive) {
    if (ws && ws.readyState === WebSocket.OPEN) {
      console.log('✅ Sending [PROJECT_MEETING_ENDED]');
      ws.send(JSON.stringify({
        type: 'message',
        project_id: currentChatId,
        text: '[PROJECT_MEETING_ENDED]'
      }));
    } else {
      console.warn('❌ WS not open, cannot send Ended message');
    }
  }

  // Cleanup Peers
  Object.values(projectPeers).forEach(pc => pc.close());
  projectPeers = {};

  if (container) container.innerHTML = '';

  // Notify others (optional, mesh usually relies on connection failure or explicit leave)
};

// Handle incoming RTC signals for Project
function handleProjectRTC(data) {
  const fromId = Number(data.from_id);
  if (fromId === Number(currentUserId)) return;

  // If I am not in the meeting (overlay hidden), ignore signals
  const overlay = document.getElementById('meeting-overlay');
  if (!overlay || overlay.classList.contains('hidden')) return;

  const action = data.action;

  // New user joined: Create PC, Send Offer
  if (action === 'join_request') {
    initiateProjectCall(fromId);
    return;
  }

  // Signals coming for me?
  const toId = Number(data.to_id);
  if (toId && toId !== Number(currentUserId)) return;

  const pc = projectPeers[fromId];

  if (action === 'offer') {
    handleProjectOffer(fromId, data.sdp);
  } else if (action === 'answer') {
    if (pc) pc.setRemoteDescription(new RTCSessionDescription(data.sdp));
  } else if (action === 'candidate') {
    if (pc && data.candidate) {
      try {
        pc.addIceCandidate(new RTCIceCandidate(data.candidate));
      } catch (e) { console.warn('ICE Add Error', e); }
    }
  } else if (action === 'raise_hand') {
    updateRemoteHandStatus(fromId, data.raised);
  } else if (action === 'reaction') {
    showFlyingReaction(fromId, data.content);
  }
}

async function initiateProjectCall(targetId) {
  if (projectPeers[targetId]) return; // Already connected

  const pc = createPeerConnection(targetId);
  projectPeers[targetId] = pc;

  // Add local tracks
  projectLocalStream.getTracks().forEach(track => pc.addTrack(track, projectLocalStream));

  // Create Offer
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);

  sendProjectRTC({
    action: 'offer',
    to_id: targetId,
    sdp: offer
  });
}

async function handleProjectOffer(fromId, sdp) {
  let pc = projectPeers[fromId];
  if (!pc) {
    pc = createPeerConnection(fromId);
    projectPeers[fromId] = pc;
    // Add local tracks
    if (projectLocalStream) {
      projectLocalStream.getTracks().forEach(track => pc.addTrack(track, projectLocalStream));
    }
  }

  await pc.setRemoteDescription(new RTCSessionDescription(sdp));
  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);

  sendProjectRTC({
    action: 'answer',
    to_id: fromId,
    sdp: answer
  });
}

function createPeerConnection(remoteId) {
  const pc = new RTCPeerConnection(getRtcConfig());

  pc.onicecandidate = (event) => {
    if (event.candidate) {
      sendProjectRTC({
        action: 'candidate',
        to_id: remoteId,
        candidate: event.candidate
      });
    }
  };

  pc.ontrack = (event) => {
    // Check if video element already exists
    let existing = document.getElementById(`video-${remoteId}`);
    if (!existing) {
      addVideoTile(remoteId, event.streams[0], false);
    }
  };

  pc.onconnectionstatechange = () => {
    if (pc.connectionState === 'disconnected' || pc.connectionState === 'failed') {
      removeVideoTile(remoteId);
      pc.close();
      delete projectPeers[remoteId];
    }
  };

  return pc;
}

function addVideoTile(userId, stream, isLocal) {
  const container = document.getElementById('meeting-container');

  const wrap = document.createElement('div');
  wrap.id = `video-wrapper-${userId}`;
  wrap.style.position = 'relative';
  wrap.style.aspectRatio = '16/9';
  wrap.style.background = '#111';
  wrap.style.borderRadius = '8px';
  wrap.style.overflow = 'hidden';
  wrap.style.boxShadow = '0 2px 5px rgba(0,0,0,0.5)';

  const vid = document.createElement('video');
  vid.id = `video-${userId}`;
  vid.autoplay = true;
  vid.playsInline = true;
  if (isLocal) vid.muted = true; // Avoid feedback
  vid.srcObject = stream;
  vid.style.width = '100%';
  vid.style.height = '100%';
  vid.style.objectFit = 'cover';

  const label = document.createElement('div');
  label.textContent = isLocal ? "You" : `User ${userId}`;
  label.style.position = 'absolute';
  label.style.bottom = '8px';
  label.style.left = '8px';
  label.style.background = 'rgba(0,0,0,0.6)';
  label.style.padding = '4px 8px';
  label.style.borderRadius = '4px';
  label.style.color = 'white';
  label.style.fontSize = '12px';

  wrap.appendChild(vid);
  wrap.appendChild(label);
  container.appendChild(wrap);
}

function removeVideoTile(userId) {
  const wrap = document.getElementById(`video-wrapper-${userId}`);
  if (wrap) wrap.remove();
}

function sendProjectRTC(payload) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  const msg = Object.assign({ type: 'rtc' }, payload);
  ws.send(JSON.stringify(msg));
}

function confirmHostMeeting() {
  if (currentChatType !== 'project' || !currentChatId) return;

  // Simple custom modal for confirmation
  const overlay = document.createElement('div');
  overlay.id = 'host-meeting-overlay';
  overlay.style.position = 'fixed';
  overlay.style.inset = '0';
  overlay.style.background = 'rgba(0,0,0,0.5)';
  overlay.style.display = 'flex';
  overlay.style.alignItems = 'center';
  overlay.style.justifyContent = 'center';
  overlay.style.zIndex = '10000';

  const modal = document.createElement('div');
  modal.style.background = 'white';
  modal.style.padding = '24px';
  modal.style.borderRadius = '12px';
  modal.style.textAlign = 'center';
  modal.style.boxShadow = '0 20px 25px -5px rgba(0,0,0,0.1)';
  modal.style.maxWidth = '90vw';
  modal.style.width = '320px';

  const title = document.createElement('h3');
  title.textContent = 'Start Video Meeting?';
  title.style.fontSize = '18px';
  title.style.fontWeight = '700';
  title.style.marginBottom = '12px';
  title.style.color = '#111827';

  const text = document.createElement('p');
  text.textContent = 'This will start a meeting and notify everyone in the group to join.';
  text.style.fontSize = '14px';
  text.style.color = '#6b7280';
  text.style.marginBottom = '20px';

  const btnGroup = document.createElement('div');
  btnGroup.style.display = 'flex';
  btnGroup.style.gap = '10px';
  btnGroup.style.justifyContent = 'center';

  const cancelBtn = document.createElement('button');
  cancelBtn.textContent = 'Cancel';
  cancelBtn.style.padding = '8px 16px';
  cancelBtn.style.border = '1px solid #d1d5db';
  cancelBtn.style.background = 'white';
  cancelBtn.style.borderRadius = '6px';
  cancelBtn.style.cursor = 'pointer';
  cancelBtn.onclick = () => overlay.remove();

  const hostBtn = document.createElement('button');
  hostBtn.textContent = 'Host Meeting';
  hostBtn.style.padding = '8px 16px';
  hostBtn.style.border = 'none';
  hostBtn.style.background = '#2563eb';
  hostBtn.style.color = 'white';
  hostBtn.style.borderRadius = '6px';
  hostBtn.style.fontWeight = '600';
  hostBtn.style.cursor = 'pointer';
  hostBtn.onclick = () => {
    overlay.remove();
    startHostingMeeting();
  };

  btnGroup.appendChild(cancelBtn);
  btnGroup.appendChild(hostBtn);
  modal.appendChild(title);
  modal.appendChild(text);
  modal.appendChild(btnGroup);
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
}

function startHostingMeeting() {
  openProjectMeeting();
  // Send invite
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      type: 'message',
      project_id: currentChatId,
      text: '[PROJECT_MEETING_INVITE]'
    }));
  }
}

function joinMeetingFromInvite() {
  openProjectMeeting();
}



function openCallOverlay(kind, incoming) {
  const overlay = document.getElementById('call-overlay');
  const title = document.getElementById('call-title');
  const acceptBtn = document.getElementById('call-accept-btn');
  const rejectBtn = document.getElementById('call-reject-btn');
  if (!overlay) return;
  overlay.classList.remove('hidden');
  overlay.style.display = 'flex';
  if (title) title.textContent = (incoming ? 'Incoming ' : 'Calling ') + (kind === 'video' ? 'Video' : 'Voice');
  if (acceptBtn) acceptBtn.style.display = incoming ? 'inline-block' : 'none';
  if (rejectBtn) rejectBtn.style.display = incoming ? 'inline-block' : 'none';
}

function closeCallOverlay() {
  const overlay = document.getElementById('call-overlay');
  if (overlay) { overlay.classList.add('hidden'); overlay.style.display = 'none'; }
}

async function startOutgoingCall(kind) {
  if (currentChatType !== 'user' || !currentChatId || !ws || ws.readyState !== WebSocket.OPEN) return;
  rtcCallType = kind;
  openCallOverlay(kind, false);
  const constraints = { audio: true, video: kind === 'video' ? { width: { ideal: 1280 }, height: { ideal: 720 } } : false };
  try {
    rtcLocalStream = await navigator.mediaDevices.getUserMedia(constraints);
  } catch (e) {
    console.error('Error accessing media devices:', e);
    alert(`Could not access camera/microphone. Error: ${e.name}: ${e.message}\n\nNote: If you are not on localhost or HTTPS, browsers block camera access. Check "chrome://flags/#unsafely-treat-insecure-origin-as-secure" if testing on HTTP.`);
    closeCallOverlay();
    return;
  }
  const lv = document.getElementById('local-video');
  if (lv) lv.srcObject = rtcLocalStream;
  rtcPeer = new RTCPeerConnection(getRtcConfig());
  rtcLocalStream.getTracks().forEach(t => rtcPeer.addTrack(t, rtcLocalStream));
  rtcPeer.ontrack = (ev) => { const rv = document.getElementById('remote-video'); if (rv) rv.srcObject = ev.streams[0]; };
  rtcPeer.onicecandidate = (ev) => { if (ev.candidate) sendRTC('candidate', { candidate: ev.candidate }); };
  const offer = await rtcPeer.createOffer();
  await rtcPeer.setLocalDescription(offer);
  sendRTC('offer', { sdp: offer, call_type: kind });
}

async function acceptIncomingCall() {
  if (!rtcIncomingOffer) return;
  const kind = rtcIncomingOffer.call_type === 'video' ? 'video' : 'audio';
  rtcCallType = kind;
  const constraints = { audio: true, video: kind === 'video' ? { width: { ideal: 1280 }, height: { ideal: 720 } } : false };
  try { rtcLocalStream = await navigator.mediaDevices.getUserMedia(constraints); } catch (e) { endCall(); return; }
  const lv = document.getElementById('local-video');
  if (lv) lv.srcObject = rtcLocalStream;
  rtcPeer = new RTCPeerConnection(getRtcConfig());
  rtcLocalStream.getTracks().forEach(t => rtcPeer.addTrack(t, rtcLocalStream));
  rtcPeer.ontrack = (ev) => { const rv = document.getElementById('remote-video'); if (rv) rv.srcObject = ev.streams[0]; };
  rtcPeer.onicecandidate = (ev) => { if (ev.candidate) sendRTC('candidate', { candidate: ev.candidate }); };
  await rtcPeer.setRemoteDescription(new RTCSessionDescription(rtcIncomingOffer.sdp));
  const answer = await rtcPeer.createAnswer();
  await rtcPeer.setLocalDescription(answer);
  sendRTC('answer', { sdp: answer, call_type: kind });
  const acceptBtn = document.getElementById('call-accept-btn');
  const rejectBtn = document.getElementById('call-reject-btn');
  if (acceptBtn) acceptBtn.style.display = 'none';
  if (rejectBtn) rejectBtn.style.display = 'none';
}

function sendRTC(action, payload) {
  const body = Object.assign({ type: 'rtc', action, to: Number(currentChatId), call_type: rtcCallType, from: Number(currentUserId) }, payload || {});
  if (rtcPeerToId) body.to = rtcPeerToId;
  const msg = JSON.stringify(body);
  let sent = false;
  if (ws && ws.readyState === WebSocket.OPEN) { try { ws.send(msg); sent = true; } catch (e) { } }
  if (notifyWS && notifyWS.readyState === WebSocket.OPEN) { try { notifyWS.send(msg); sent = true; } catch (e) { } }
  if (!sent) console.warn('RTC signal not sent: no WS channels open');
}

// Optional keepalive pings to prevent idle disconnects (harmless on server)
setInterval(() => {
  try {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'ping' }));
    if (notifyWS && notifyWS.readyState === WebSocket.OPEN) notifyWS.send(JSON.stringify({ type: 'ping' }));
  } catch (e) { }
}, 30000);

function endCall() {
  try { if (rtcPeer) rtcPeer.close(); } catch (e) { }
  rtcPeer = null;
  try { if (rtcLocalStream) rtcLocalStream.getTracks().forEach(t => t.stop()); } catch (e) { }
  rtcLocalStream = null;
  rtcIncomingOffer = null;
  rtcPeerToId = null;
  closeCallOverlay();
}
let notifyWS = null;
let notifyReconnectAttempts = 0;
function connectNotifySocket() {
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${protocol}//${window.location.host}/ws/notify/`;
  try { if (notifyWS && notifyWS.readyState === WebSocket.OPEN) notifyWS.close(); } catch (e) { }
  try {
    notifyWS = new WebSocket(url);
  } catch (e) {
    return;
  }
  notifyWS.onmessage = (evt) => {
    try {
      const data = JSON.parse(evt.data);
      if (data && data.type === 'rtc') handleWebSocketMessage(data);
    } catch (e) { }
  };
  notifyWS.onopen = () => { notifyReconnectAttempts = 0; };
  notifyWS.onclose = () => {
    notifyReconnectAttempts++;
    const backoff = Math.min(1000 * (2 ** (notifyReconnectAttempts - 1)), 30000);
    setTimeout(connectNotifySocket, backoff);
  };
}

/* ============================================================
   MEETING CONTROLS
   ============================================================ */

function toggleMeetingCam() {
  if (projectLocalStream) {
    const vidTrack = projectLocalStream.getVideoTracks()[0];
    if (vidTrack) {
      vidTrack.enabled = !vidTrack.enabled;
      updateMeetingBtnState('meeting-cam-btn', vidTrack.enabled);
    }
  }
}

function toggleMeetingMic() {
  if (projectLocalStream) {
    const audTrack = projectLocalStream.getAudioTracks()[0];
    if (audTrack) {
      audTrack.enabled = !audTrack.enabled;
      updateMeetingBtnState('meeting-mic-btn', audTrack.enabled);
    }
  }
}

function updateMeetingBtnState(id, enabled) {
  const btn = document.getElementById(id);
  if (!btn) return;
  if (enabled) {
    btn.style.background = '';
    btn.style.color = '';
  } else {
    btn.style.background = '#dc2626';
    btn.style.color = 'white';
    btn.style.borderColor = '#b91c1c';
  }
}

async function toggleScreenShare() {
  if (isScreenSharing) {
    stopScreenShare();
    return;
  }

  try {
    const stream = await navigator.mediaDevices.getDisplayMedia({ video: true });
    const screenTrack = stream.getVideoTracks()[0];

    // Keep reference to original cam track
    if (projectLocalStream) {
      originalVideoTrack = projectLocalStream.getVideoTracks()[0];
    }

    // Replace track in local stream (for self view)
    if (projectLocalStream) {
      projectLocalStream.removeTrack(originalVideoTrack);
      projectLocalStream.addTrack(screenTrack);
    }

    // Update Local Video Element
    const localVideo = document.getElementById(`video-${currentUserId}`);
    if (localVideo) localVideo.srcObject = projectLocalStream;

    // Replace track in all PeerConnections
    Object.values(projectPeers).forEach(pc => {
      const sender = pc.getSenders().find(s => s.track.kind === 'video');
      if (sender) {
        sender.replaceTrack(screenTrack);
      }
    });

    // Handle user stopping share via browser UI
    screenTrack.onended = () => stopScreenShare();

    isScreenSharing = true;
    const btn = document.getElementById('meeting-share-btn');
    if (btn) {
      btn.style.background = '#2563eb'; // Blue to indicate active
      btn.style.color = 'white';
    }

  } catch (e) {
    console.error('Error sharing screen:', e);
  }
}

function stopScreenShare() {
  if (!isScreenSharing) return;

  // Stop screen track
  const screenTrack = projectLocalStream.getVideoTracks()[0];
  if (screenTrack) screenTrack.stop();

  // Restore camera track
  if (originalVideoTrack) {
    projectLocalStream.removeTrack(screenTrack);
    projectLocalStream.addTrack(originalVideoTrack);
    // Important: Re-enable if it was enabled before? Assuming yes.
    originalVideoTrack.enabled = true;
  }

  // Update Local Video
  const localVideo = document.getElementById(`video-${currentUserId}`);
  if (localVideo) localVideo.srcObject = projectLocalStream;

  // Replace track in peers
  Object.values(projectPeers).forEach(pc => {
    const sender = pc.getSenders().find(s => s.track.kind === 'video');
    if (sender && originalVideoTrack) {
      sender.replaceTrack(originalVideoTrack);
    }
  });

  isScreenSharing = false;
  originalVideoTrack = null;
  const btn = document.getElementById('meeting-share-btn');
  if (btn) {
    btn.style.background = '';
    btn.style.color = '';
  }
}

function inviteToMeeting() {
  // 1. Send invite to group chat
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      type: 'message',
      project_id: currentChatId,
      text: '[PROJECT_MEETING_INVITE]'
    }));
  }

  // 2. Copy link to clipboard
  const uniqueLink = `${window.location.origin}/chat/project/${currentProjectId}`;
  navigator.clipboard.writeText(`Join my meeting: ${uniqueLink}`).then(() => {
    alert('Invite sent to group & Link copied to clipboard!');
  }).catch(() => {
    alert('Invite sent to group!');
  });
}

function toggleMeetingSize() {
  const overlay = document.getElementById('meeting-overlay');
  if (overlay) overlay.classList.toggle('minimized');
}

/* ============================================================
   MEETING REACTIONS & RAISE HAND
   ============================================================ */

function toggleRaiseHand() {
  isHandRaised = !isHandRaised;

  // Update local UI
  const btn = document.getElementById('meeting-hand-btn');
  if (btn) {
    if (isHandRaised) {
      btn.style.background = '#eab308'; // yellow
      btn.style.color = '#fff';
    } else {
      btn.style.background = '';
      btn.style.color = '';
    }
  }

  // Update local badge
  updateRemoteHandStatus(currentUserId, isHandRaised);

  // Broadcast to peers
  sendProjectRTC({
    action: 'raise_hand',
    raised: isHandRaised
  });
}

function updateRemoteHandStatus(userId, raised) {
  const wrap = document.getElementById(`video-wrapper-${userId}`);
  if (!wrap) return;

  let badge = wrap.querySelector('.video-hand-badge');
  if (raised) {
    if (!badge) {
      badge = document.createElement('div');
      badge.className = 'video-hand-badge';
      badge.textContent = '✋';
      wrap.appendChild(badge);
    }
  } else {
    if (badge) badge.remove();
  }
}

function sendMeetingReaction(emoji) {
  // Hide popup
  const popup = document.getElementById('reactions-popup');
  if (popup) popup.classList.add('hidden');

  // Show locally
  showFlyingReaction(currentUserId, emoji);

  // Broadcast
  sendProjectRTC({
    action: 'reaction',
    content: emoji
  });
}

function showFlyingReaction(userId, emoji) {
  const overlay = document.getElementById('meeting-container'); // use container to constrain to video area? No, overlay is better for global center
  if (!overlay) return;

  const el = document.createElement('div');
  el.className = 'flying-reaction';
  el.textContent = emoji;

  // If we know who sent it, maybe position it over their video? 
  // For now, let's random position slightly to make it fun or center it. 
  // The CSS default was center bottom. Let's add slight random X offset.
  const randomX = (Math.random() - 0.5) * 50; // -25% to +25%
  el.style.transform = `translateX(calc(-50% + ${randomX}px))`;

  // Append to a wrapper that sits on top of video grid
  // We'll just append to meeting-container but ensure z-index is high
  overlay.appendChild(el);

  // Remove after animation
  setTimeout(() => el.remove(), 2000);
}



/* ============================================================
   GROUP CREATION LOGIC
   ============================================================ */

/* ============================================================
   GROUP CREATION LOGIC
   ============================================================ */

function setupGroupCreationListeners() {
  console.log('init group creation listeners');

  // --- HEADER MENU LOGIC ---
  const menuBtn = document.getElementById('header-menu-btn');
  const dropdown = document.getElementById('header-menu-dropdown');

  if (menuBtn && dropdown) {
    menuBtn.onclick = (e) => {
      e.stopPropagation();
      dropdown.classList.toggle('active');
    };

    // Close on click outside
    document.addEventListener('click', (e) => {
      if (!dropdown.contains(e.target) && !menuBtn.contains(e.target)) {
        dropdown.classList.remove('active');
      }
    });
  }

  // --- MENU ITEMS ---
  const createGroupItem = document.getElementById('menu-create-group');
  if (createGroupItem) {
    createGroupItem.onclick = (e) => {
      e.stopPropagation();
      if (dropdown) dropdown.classList.remove('active');
      openGroupCreationModal();
    };
  }

  const hostMeetingItem = document.getElementById('menu-host-meeting');
  if (hostMeetingItem) {
    hostMeetingItem.onclick = (e) => {
      e.stopPropagation();
      if (dropdown) dropdown.classList.remove('active');
      // For now, treat Host Meeting like creating a group to meet in
      openGroupCreationModal();
    };
  }



  const settingsItem = document.getElementById('menu-settings');
  if (settingsItem) {
    settingsItem.onclick = (e) => {
      e.stopPropagation();
      if (dropdown) dropdown.classList.remove('active');
      if (currentUserId) openMemberProfile(currentUserId);
    };
  }

  // --- GROUP CREATION OVERLAY LOGIC ---
  const overlay = document.getElementById('create-group-overlay');
  const closeBtn = document.getElementById('close-group-btn');
  const submitBtn = document.getElementById('submit-group-btn');
  const addUsersBtn = document.getElementById('group-add-users-btn');

  // Support old button if it still exists (backwards compat or if partial deploy)
  const openBtn = document.getElementById('create-group-btn');
  if (openBtn) {
    openBtn.onclick = (e) => {
      e.stopPropagation();
      openGroupCreationModal();
    };
  }

  if (closeBtn) {
    closeBtn.onclick = () => {
      if (typeof closeGroupCreationModal === 'function') closeGroupCreationModal();
      else if (overlay) {
        overlay.classList.add('hidden');
        overlay.style.display = 'none';
      }
    };
  }

  // Close on click outside
  if (overlay) {
    overlay.onclick = (e) => {
      if (e.target === overlay) {
        if (typeof closeGroupCreationModal === 'function') closeGroupCreationModal();
        else {
          overlay.classList.add('hidden');
          overlay.style.display = 'none';
        }
      }
    };
  }

  // Logic for "Add Users" button
  if (addUsersBtn) {
    addUsersBtn.onclick = async () => {
      console.log('Add Users clicked');
      // Show user selection area
      const area = document.getElementById('group-user-selection-area');
      if (area) area.style.display = 'block';

      // Hide "Add Users" button, Show "Make Group" button
      addUsersBtn.style.display = 'none';
      if (submitBtn) submitBtn.style.display = 'block';

      // Load users
      await loadUsersForGroupCreation();
    };
  }

  // Search input listener
  const searchInput = document.getElementById('group-member-search');
  if (searchInput) {
    searchInput.oninput = (e) => {
      filterGroupMemberUsers(e.target.value);
    };
  }

  if (submitBtn) {
    submitBtn.onclick = handleGroupCreate;
  }
}

async function loadUsersForGroupCreation() {
  const container = document.getElementById('group-member-list');
  if (!container) return;
  container.innerHTML = '<div style="padding:10px; color:#6b7280;">Loading users...</div>';

  try {
    // Try list endpoint
    let users = [];
    const listRes = await fetch(`${API_BASE}/users/`, { headers: defaultHeaders() });

    if (listRes.ok) {
      users = await listRes.json();
      // Handle pagination if DRF is paginated (usually 'results' key)
      if (users.results && Array.isArray(users.results)) {
        users = users.results;
      }
    } else {
      // Fallback to searching common letters if list is restricted
      const searchRes = await fetch(`${API_BASE}/users/search/?q=a`, { headers: defaultHeaders() });
      if (searchRes.ok) users = await searchRes.json();
    }

    // Filter out current user
    if (Array.isArray(users)) {
      users = users.filter(u => u.id !== currentUserId);
      // Sort by name
      users.sort((a, b) => (a.first_name || a.username).localeCompare(b.first_name || b.username));
    } else {
      users = [];
    }

    // Store for filtering
    container.dataset.allUsers = JSON.stringify(users);

    renderGroupMemberUsers(users);

  } catch (err) {
    console.error('Error loading users:', err);
    container.innerHTML = '<div style="padding:10px; color:#ef4444;">Failed to load users</div>';
  }
}

function renderGroupMemberUsers(users) {
  const container = document.getElementById('group-member-list');
  if (!container) return;
  container.innerHTML = '';

  if (!users || users.length === 0) {
    container.innerHTML = '<div style="padding:10px; color:#6b7280;">No users found</div>';
    return;
  }

  users.forEach(user => {
    const div = document.createElement('div');
    div.className = 'compose-item';
    div.style.display = 'flex';
    div.style.alignItems = 'center';
    div.style.padding = '10px';
    div.style.cursor = 'pointer';
    div.style.borderBottom = '1px solid var(--border)';

    // Checkbox
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.value = user.id;
    checkbox.className = 'group-member-checkbox';
    checkbox.style.marginRight = '12px';
    checkbox.style.cursor = 'pointer';

    // Avatar
    const avatar = document.createElement('div');
    avatar.className = 'compose-avatar';
    avatar.textContent = (user.first_name?.[0] || user.username?.[0] || 'U').toUpperCase();
    avatar.style.marginRight = '12px';

    // Info
    const info = document.createElement('div');
    info.className = 'compose-info';

    const name = document.createElement('div');
    name.className = 'compose-name';
    name.textContent = user.first_name ? `${user.first_name} ${user.last_name}` : user.username;
    name.style.fontWeight = '600';
    name.style.fontSize = '13px';

    const username = document.createElement('div');
    username.className = 'compose-username';
    username.textContent = `@${user.username}`;
    username.style.fontSize = '11px';
    username.style.color = '#6b7280';

    info.appendChild(name);
    info.appendChild(username);

    div.appendChild(checkbox);
    div.appendChild(avatar);
    div.appendChild(info);

    // Toggle checkbox on click
    div.onclick = (e) => {
      if (e.target !== checkbox) {
        checkbox.checked = !checkbox.checked;
      }
    };

    container.appendChild(div);
  });
}

function filterGroupMemberUsers(query) {
  const container = document.getElementById('group-member-list');
  if (!container || !container.dataset.allUsers) return;

  let users = [];
  try { users = JSON.parse(container.dataset.allUsers); } catch (e) { }

  if (!query) {
    renderGroupMemberUsers(users);
    return;
  }

  const q = query.toLowerCase();
  const filtered = users.filter(u =>
    (u.first_name && u.first_name.toLowerCase().includes(q)) ||
    (u.last_name && u.last_name.toLowerCase().includes(q)) ||
    (u.username && u.username.toLowerCase().includes(q))
  );

  renderGroupMemberUsers(filtered);
}

function resetGroupCreationForm() {
  const nameInput = document.getElementById('group-name-input');
  const descInput = document.getElementById('group-desc-input');
  const searchInput = document.getElementById('group-member-search');
  const list = document.getElementById('group-member-list');
  const userArea = document.getElementById('group-user-selection-area');
  const addBtn = document.getElementById('group-add-users-btn');
  const submitBtn = document.getElementById('submit-group-btn');

  if (nameInput) nameInput.value = '';
  if (descInput) descInput.value = '';
  if (searchInput) searchInput.value = '';
  if (list) list.innerHTML = '';

  if (userArea) userArea.style.display = 'none';
  if (addBtn) addBtn.style.display = 'block';
  if (submitBtn) submitBtn.style.display = 'none';
}

async function handleGroupCreate() {
  const nameInput = document.getElementById('group-name-input');
  const descInput = document.getElementById('group-desc-input');

  const name = nameInput.value.trim();
  const description = descInput ? descInput.value.trim() : '';
  const checkboxes = document.querySelectorAll('.group-member-checkbox:checked');
  const memberIds = Array.from(checkboxes).map(cb => parseInt(cb.value));

  if (!name) {
    alert('Please enter a group name');
    return;
  }

  const data = {
    name: name,
    description: description,
    member_ids: memberIds
  };

  const btn = document.getElementById('submit-group-btn');
  if (btn) {
    btn.textContent = 'Creating...';
    btn.disabled = true;
  }

  try {
    const res = await fetch(`${API_BASE}/projects/`, {
      method: 'POST',
      headers: defaultHeaders(),
      body: JSON.stringify(data)
    });

    if (res.ok) {
      const project = await res.json();
      // Close modal
      const closeBtn = document.getElementById('close-group-btn');
      if (closeBtn) closeBtn.click();

      // Reload projects
      loadProjects();
      // Open new project
      openChat('project', project.id);
    } else {
      const err = await res.json();
      let msg = 'Failed to create group';
      if (err.name) msg = err.name[0];
      else if (err.detail) msg = err.detail;
      alert(msg);
    }
  } catch (e) {
    console.error(e);
    alert('Error creating group');
  } finally {
    if (btn) {
      btn.textContent = 'Make Group'; // Reset text
      btn.disabled = false;
    }
  }
}

function openGroupCreationModal() {
  const overlay = document.getElementById('create-group-overlay');
  if (overlay) {
    overlay.classList.remove('hidden');
    overlay.style.display = 'flex';

    // Reset view to initial state (hide user list)
    const userArea = document.getElementById('group-user-selection-area');
    const addUsersBtn = document.getElementById('group-add-users-btn');
    const submitBtn = document.getElementById('submit-group-btn');

    if (userArea) userArea.style.display = 'none';
    if (addUsersBtn) addUsersBtn.style.display = 'block';
    if (submitBtn) submitBtn.style.display = 'none';

    // Clear inputs
    resetGroupCreationForm();
  }
}

function closeGroupCreationModal() {
  const overlay = document.getElementById('create-group-overlay');
  if (overlay) {
    overlay.classList.add('hidden');
    overlay.style.display = 'none';
    resetGroupCreationForm();
  }
}

async function uploadAvatar(file) {
  const formData = new FormData();
  formData.append('avatar', file);

  try {
    const res = await fetch(`${API_BASE}/users/upload_avatar/`, {
      method: 'POST',
      headers: {
        'X-CSRFToken': getCSRFToken()
      },
      body: formData
    });

    if (res.ok) {
      const data = await res.json();
      alert('Profile picture updated!');
      // Reload unified chats to refresh avatar
      loadUnifiedChats();
      return data;
    } else {
      const err = await res.json();
      alert(err.error || 'Failed to upload avatar');
    }
  } catch (e) {
    console.error(e);
    alert('Error uploading avatar');
  }
}
