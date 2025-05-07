import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js/+esm';

const supabase = createClient(
  'https://skxzfkudduqrubtgtodp.supabase.co',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNreHpma3VkZHVxcnVidGd0b2RwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDU1ODAwNzMsImV4cCI6MjA2MTE1NjA3M30.Wj3V5-swysAz8xAbA4lKmo-NNu_mv1UW_X4BgFNq0ag'
);

const API_BASE = 'https://replyzeai.onrender.com';
let userId;

// UI Elements
const metrics = {
  processed: document.getElementById('processed-count'),
  timeSaved: document.getElementById('time-saved'),
  accuracy: document.getElementById('response-accuracy')
};

// Helpers
const showError = (message) => {
  const toast = document.createElement('div');
  toast.className = 'error-toast';
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 5000);
};

const formatTime = (minutes) => {
  const hours = Math.floor(minutes / 60);
  const mins = minutes % 60;
  return `${hours}h ${mins}m`;
};

// API Calls
const fetchWithAuth = async (url) => {
  const { data: { session } } = await supabase.auth.getSession();
  
  const response = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${session.access_token}`
    }
  });
  
  if (!response.ok) {
    throw new Error(`API request failed: ${response.status}`);
  }
  
  return response.json();
};

// Data Loading
const loadMetrics = async () => {
  try {
    const data = await fetchWithAuth(`${API_BASE}/api/metrics`);
    
    metrics.processed.textContent = data.processed;
    metrics.timeSaved.textContent = formatTime(data.time_saved);
    metrics.accuracy.textContent = data.processed > 0 
      ? `${data.accuracy.toFixed(1)}%` 
      : '—';
      
  } catch (error) {
    showError('Failed to load metrics');
    console.error('Metrics error:', error);
  }
};

const loadActivities = async () => {
  try {
    const { activities } = await fetchWithAuth(`${API_BASE}/api/activities`);
    renderActivities(activities);
  } catch (error) {
    showError('Failed to load recent activities');
    console.error('Activities error:', error);
  }
};

const renderActivities = (activities) => {
  const container = document.getElementById('activity-container');
  container.innerHTML = activities.length === 0
    ? '<div class="activity-item">No recent activities found</div>'
    : activities.map(activity => `
        <div class="activity-item">
          <div class="activity-header">
            <div class="activity-contact">${activity.sender_email}</div>
            <div class="activity-time">${new Date(activity.created_at).toLocaleString()}</div>
          </div>
          <div class="activity-content">${activity.processed_content}</div>
          <div class="activity-actions">
            <button class="action-btn" onclick="window.openDetail('${activity.id}')">
              <i class="fas fa-eye"></i>Review
            </button>
          </div>
        </div>
      `).join('');
};

// Realtime Updates
const setupRealtime = () => {
  return supabase.channel('emails')
    .on('postgres_changes', {
      event: '*',
      schema: 'public',
      table: 'emails',
      filter: `user_id=eq.${userId}`
    }, () => {
      loadMetrics();
      loadActivities();
    })
    .subscribe();
};

// Initialization
const initDashboard = async () => {
  try {
    const { data: { session }, error } = await supabase.auth.getSession();
    
    if (error || !session) {
      window.location.href = '/login';
      return;
    }
    
    userId = session.user.id;
    
    // Load initial data
    await Promise.all([loadMetrics(), loadActivities()]);
    setupRealtime();
    
    // Event listeners
    document.getElementById('logout-btn').addEventListener('click', async () => {
      await supabase.auth.signOut();
      window.location.href = '/login';
    });
    
    document.getElementById('configure-btn').addEventListener('click', () => {
      window.location.href = '/configure';
    });

  } catch (error) {
    console.error('Initialization error:', error);
    window.location.href = '/login';
  }
};

// Start the dashboard
initDashboard();
