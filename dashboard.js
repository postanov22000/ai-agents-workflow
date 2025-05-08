import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js/+esm';

const supabaseUrl = document.querySelector('meta[name="supabase-url"]').content;
const supabaseAnonKey = document.querySelector('meta[name="supabase-anon-key"]').content;
const API_BASE = 'https://replyzeai.onrender.com';

const supabase = createClient(supabaseUrl, supabaseAnonKey);
let userId;
let realtimeChannel;

const elements = {
  processedCount: document.getElementById('processed-count'),
  timeSaved: document.getElementById('time-saved'),
  responseAccuracy: document.getElementById('response-accuracy'),
  activityContainer: document.getElementById('activity-container'),
  responderStatus: document.getElementById('responder-status'),
  logoutBtn: document.getElementById('logout-btn'),
  configureBtn: document.getElementById('configure-btn'),
  pauseBtn: document.getElementById('pause-responder')
};

const showToast = (message, isError = true) => {
  const toast = document.createElement('div');
  toast.className = `toast ${isError ? 'error' : 'success'}`;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 5000);
};

const formatDate = (isoString) => {
  try {
    return new Date(isoString).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  } catch {
    return 'Invalid date';
  }
};

const fetchAPI = async (endpoint) => {
  try {
    const { data: { session }, error: authError } = await supabase.auth.getSession();
    
    if (authError || !session) {
      showToast('Session expired. Please login again.');
      window.location.href = '/login';
      return;
    }

    const response = await fetch(`${API_BASE}${endpoint}`, {
      headers: {
        'Authorization': `Bearer ${session.access_token}`
      }
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    showToast(`API Error: ${error.message}`);
    throw error;
  }
};

const loadMetrics = async () => {
  try {
    const data = await fetchAPI('/api/metrics');
    
    elements.processedCount.textContent = data.processed?.toLocaleString() || '0';
    elements.timeSaved.textContent = data.time_saved ? 
      `${Math.floor(data.time_saved / 60)}h ${data.time_saved % 60}m` : '0m';
    elements.responseAccuracy.textContent = data.processed > 0 
      ? `${(data.accuracy || 0).toFixed(1)}%` 
      : '—';
  } catch (error) {
    console.error('Metrics load error:', error);
    elements.processedCount.textContent = '—';
    elements.timeSaved.textContent = '—';
    elements.responseAccuracy.textContent = '—';
  }
};

const loadActivities = async () => {
  try {
    const data = await fetchAPI('/api/activities');
    
    if (!data?.activities) {
      throw new Error('Invalid activities data');
    }

    renderActivities(data.activities);
  } catch (error) {
    console.error('Activities load error:', error);
    elements.activityContainer.innerHTML = `
      <div class="activity-item">
        <div class="activity-content">Failed to load activities. ${error.message}</div>
      </div>
    `;
  }
};

const renderActivities = (activities) => {
  elements.activityContainer.innerHTML = activities.length > 0
    ? activities.map(activity => `
        <div class="activity-item">
          <div class="activity-header">
            <div class="activity-contact">${activity.sender_email || 'Unknown sender'}</div>
            <div class="activity-time">${formatDate(activity.created_at)}</div>
          </div>
          <div class="activity-content">${activity.processed_content?.substring(0, 120) + (activity.processed_content?.length > 120 ? '...' : '') || 'No content available'}</div>
          <div class="activity-actions">
            <button class="action-btn" data-email-id="${activity.id}">
              <i class="fas fa-eye"></i>Review
            </button>
            <span class="status-badge ${activity.status}">${activity.status}</span>
          </div>
        </div>
      `).join('')
    : '<div class="activity-item">No recent activities found</div>';
};

const setupRealtime = () => {
  if (realtimeChannel) {
    realtimeChannel.unsubscribe();
  }

  realtimeChannel = supabase.channel('emails-channel')
    .on('postgres_changes', {
      event: 'INSERT',
      schema: 'public',
      table: 'emails',
      filter: `user_id=eq.${userId}`
    }, handleRealtimeUpdate)
    .on('postgres_changes', {
      event: 'UPDATE',
      schema: 'public',
      table: 'emails',
      filter: `user_id=eq.${userId}`
    }, handleRealtimeUpdate)
    .subscribe(status => {
      elements.responderStatus.textContent = 
        status === 'SUBSCRIBED' ? 'Active' : 'Connection Issues';
    });
};

const handleRealtimeUpdate = (payload) => {
  showToast(`New email update: ${payload.eventType}`, false);
  loadMetrics();
  loadActivities();
};

const setupEventListeners = () => {
  elements.logoutBtn.addEventListener('click', async () => {
    try {
      const { error } = await supabase.auth.signOut();
      if (error) throw error;
      window.location.href = '/login';
    } catch (error) {
      showToast('Logout failed. Please try again.');
    }
  });

  elements.configureBtn.addEventListener('click', () => {
    window.location.href = '/configure';
  });

  elements.pauseBtn.addEventListener('click', async () => {
    try {
      const { error } = await supabase
        .from('user_settings')
        .update({ responder_enabled: false })
        .eq('user_id', userId);
      
      if (error) throw error;
      showToast('Responder paused successfully', false);
      elements.pauseBtn.innerHTML = '<i class="fas fa-play"></i>Resume Responder';
      elements.pauseBtn.id = 'resume-responder';
    } catch (error) {
      showToast('Failed to pause responder');
    }
  });

  elements.activityContainer.addEventListener('click', async (e) => {
    const btn = e.target.closest('.action-btn');
    if (btn) {
      const emailId = btn.dataset.emailId;
      try {
        const { data, error } = await supabase
          .from('emails')
          .select('*')
          .eq('id', emailId)
          .single();
        
        if (error) throw error;
        window.open(`/email-detail/${emailId}`, '_blank');
      } catch (error) {
        showToast('Failed to load email details');
      }
    }
  });
};

const initDashboard = async () => {
  try {
    const { data: { session }, error } = await supabase.auth.getSession();
    
    if (error || !session?.user) {
      window.location.href = '/login';
      return;
    }

    userId = session.user.id;
    
    await Promise.allSettled([loadMetrics(), loadActivities()]);
    setupRealtime();
    setupEventListeners();
    
    // Initial status update
    elements.responderStatus.textContent = 'Active';

  } catch (error) {
    showToast('Dashboard initialization failed');
    console.error('Dashboard init error:', error);
    setTimeout(() => window.location.reload(), 3000);
  }
};

document.addEventListener('DOMContentLoaded', initDashboard);
