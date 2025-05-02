// dashboard.js
import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js/+esm';

// Supabase client
const supabase = createClient(
  'https://skxzfkudduqrubtgtodp.supabase.co',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNreHpma3VkZHVxcnVidGd0b2RwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDU1ODAwNzMsImV4cCI6MjA2MTE1NjA3M30.Wj3V5-swysAz8xAbA4lKmo-NNu_mv1UW_X4BgFNq0ag'
);

// Global state
let userId;
let realtimeChannel;

// Helpers
const getTodayISO = () => {
  const date = new Date();
  date.setUTCHours(0, 0, 0, 0);
  return date.toISOString();
};

const updateUILoading = (loading) => {
  document.querySelectorAll('[aria-live]').forEach(el => {
    el.setAttribute('aria-busy', loading);
    el.textContent = loading ? '—' : el.textContent;
  });
};

// Metrics
async function loadMetrics() {
  updateUILoading(true);
  try {
    const { count: processed } = await supabase
      .from('emails')
      .select('id', { count: 'exact' })
      .eq('user_id', userId)
      .gte('created_at', getTodayISO());

    const { count: completed } = await supabase
      .from('emails')
      .select('id', { count: 'exact' })
      .eq('user_id', userId)
      .eq('status', 'complete')
      .gte('created_at', getTodayISO());

    document.getElementById('processed-count').textContent = processed || 0;
    document.getElementById('time-saved').textContent = 
      `${((processed * 5) / 60).toFixed(1)}h`;
    document.getElementById('response-accuracy').textContent = 
      processed ? `${((completed / processed) * 100).toFixed(1)}%` : '—';
  } catch (error) {
    console.error('Metrics error:', error);
  }
  updateUILoading(false);
}

// Activity Feed
async function loadRecentReplies() {
  try {
    const { data: recent } = await supabase
      .from('emails')
      .select('sender_email,subject,ai_response,created_at')
      .eq('user_id', userId)
      .eq('status', 'complete')
      .order('created_at', { ascending: false })
      .limit(5);

    const container = document.getElementById('activity-container');
    container.innerHTML = '';

    (recent || []).forEach(email => {
      container.appendChild(createActivityItem(email));
    });
  } catch (error) {
    console.error('Activity feed error:', error);
  }
}

function createActivityItem(email) {
  const d = document.createElement('div');
  d.className = 'activity-item';
  d.innerHTML = `
    <div class="activity-header">
      <div class="activity-contact">${email.sender_email}</div>
      <div class="activity-time">${new Date(email.created_at).toLocaleString()}</div>
    </div>
    <div class="activity-content">${email.ai_response}</div>
    <div class="activity-actions">
      <button class="action-btn"><i class="fas fa-eye"></i>Review</button>
      <button class="action-btn"><i class="fas fa-copy"></i>Template</button>
    </div>`;
  return d;
}

// Real-time
function setupRealtime() {
  realtimeChannel = supabase.channel('emails-channel')
    .on('postgres_changes', {
      event: '*',
      schema: 'public',
      table: 'emails',
      filter: `user_id=eq.${userId}`
    }, async (payload) => {
      await loadMetrics();
      
      if (payload.eventType === 'INSERT' && payload.new.status === 'complete') {
        const container = document.getElementById('activity-container');
        container.prepend(createActivityItem(payload.new));
        if (container.children.length > 5) container.lastElementChild.remove();
      }
    })
    .subscribe((status) => {
      if (status === 'CHANNEL_ERROR') {
        console.error('Realtime connection failed');
        setTimeout(setupRealtime, 5000); // Reconnect after 5s
      }
    });
}

// Init
(async () => {
  try {
    // Auth check
    const { data: { session }, error } = await supabase.auth.getSession();
    if (error || !session?.user) throw new Error('No session');
    userId = session.user.id;

    // Logout handler
    document.getElementById('logout-btn').addEventListener('click', async () => {
      await supabase.auth.signOut();
      window.location.href = 'signup.html';
    });

    // Load initial data
    await Promise.all([loadMetrics(), loadRecentReplies()]);
    setupRealtime();
    
    // Update status
    document.getElementById('responder-status').textContent = 'Active';
    
  } catch (error) {
    console.error('Initialization error:', error);
    window.location.href = 'signup.html';
  }
})();
