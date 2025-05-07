// dashboard.js
import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js/+esm';

// Configuration from HTML meta tags
const supabaseUrl = document.querySelector('meta[name="supabase-url"]').content;
const supabaseAnonKey = document.querySelector('meta[name="supabase-anon-key"]').content;
const API_BASE = 'https://replyzeai.onrender.com';

// Initialize Supabase
const supabase = createClient(supabaseUrl, supabaseAnonKey);

// State
let userId;
let realtimeChannel;

// DOM Elements
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

// Helpers
const showToast = (message, isError = true) => {
  const toast = document.createElement('div');
  toast.className = `toast ${isError ? 'error' : 'success'}`;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 5000);
};

const formatDate = (isoString) => {
  return new Date(isoString).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
};

// API Fetch Wrapper
const fetchAPI = async (endpoint) => {
  try {
    const { data: { session } } = await supabase.auth.getSession();
    
    const response = await fetch(`${API_BASE}${endpoint}`, {
      headers: {
        'Authorization': `Bearer ${session.access_token}`
      }
    });

    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
    return await response.json();
  } catch (error) {
    showToast(`API Error: ${error.message}`);
    throw error;
  }
};

// Data Loading
const loadMetrics = async () => {
  try {
    const data = await fetchAPI('/api/metrics');
    
    elements.processedCount.textContent = data.processed;
    elements.timeSaved.textContent = `${Math.floor(data.time_saved / 60)}h ${data.time_saved % 60}m`;
    elements.responseAccuracy.textContent = data.processed > 0 
      ? `${data.accuracy.toFixed(1)}%` 
      : '—';
  } catch (error) {
    console.error('Metrics load failed:', error);
  }
};

const loadActivities = async () => {
  try {
    const { activities } = await fetchAPI('/api/activities');
    renderActivities(activities);
  } catch (error) {
    console.error('Activities load failed:', error);
  }
};

const renderActivities = (activities) => {
  elements.activityContainer.innerHTML = activities.length > 0
    ? activities.map(activity => `
        <div class="activity-item">
          <div class="activity-header">
            <div class="activity-contact">${activity.sender_email}</div>
            <div class="activity-time">${formatDate(activity.created_at)}</div>
          </div>
          <div class="activity-content">${activity.processed_content}</div>
          <div class="activity-actions">
            <button class="action-btn" data-email-id="${activity.id}">
              <i class="fas fa-eye"></i>Review
            </button>
          </div>
        </div>
      `).join('')
    : '<div class="activity-item">No recent activities found</div>';
};

// Realtime Updates
const setupRealtime = () => {
  realtimeChannel = supabase.channel('emails-channel')
    .on('postgres_changes', {
      event: '*',
      schema: 'public',
      table: 'emails',
      filter: `user_id=eq.${userId}`
    }, () => {
      loadMetrics();
      loadActivities();
    })
    .subscribe(status => {
      elements.responderStatus.textContent = 
        status === 'SUBSCRIBED' ? 'Active' : 'Connection Issues';
    });
};

// Event Handlers
const setupEventListeners = () => {
  elements.logoutBtn.addEventListener('click', async () => {
    await supabase.auth.signOut();
    window.location.href = '/login';
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
    } catch (error) {
      showToast('Failed to pause responder');
    }
  });

  elements.activityContainer.addEventListener('click', (e) => {
    const btn = e.target.closest('.action-btn');
    if (btn) {
      const emailId = btn.dataset.emailId;
      window.open(`/email-detail/${emailId}`, '_blank');
    }
  });
};

// Initialization
const initDashboard = async () => {
  try {
    const { data: { session }, error } = await supabase.auth.getSession();
    
    if (error || !session?.user) {
      window.location.href = '/login';
      return;
    }

    userId = session.user.id;
    await Promise.all([loadMetrics(), loadActivities()]);
    setupRealtime();
    setupEventListeners();
    elements.responderStatus.textContent = 'Active';

  } catch (error) {
    console.error('Dashboard init failed:', error);
    window.location.href = '/login';
  }
};

// Start the Dashboard
document.addEventListener('DOMContentLoaded', initDashboard);
