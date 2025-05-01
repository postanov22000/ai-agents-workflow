// dashboard.js
import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js/+esm';

// Replace with your actual Supabase project URL and anon key
const supabase = createClient('https://skxzfkudduqrubtgtodp.supabase.co', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNreHpma3VkZHVxcnVidGd0b2RwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDU1ODAwNzMsImV4cCI6MjA2MTE1NjA3M30.Wj3V5-swysAz8xAbA4lKmo-NNu_mv1UW_X4BgFNq0ag');

// Wait for session to load before doing anything
const { data: { session }, error: sessionError } = await supabase.auth.getSession();

if (sessionError || !session || !session.user) {
  console.warn("No session or user found. Redirecting to signup...");
  window.location.href = 'signup.html';
} else {
  const user = session.user;
  const userId = user.id;

  // Get today's date in ISO
  const isoToday = new Date();
  isoToday.setUTCHours(0, 0, 0, 0);

  // Fetch email stats for today
  async function loadEmailStats() {
    const { count: processed } = await supabase
      .from('emails')
      .select('id', { count: 'exact' })
      .eq('user_id', userId)
      .gte('created_at', isoToday.toISOString());

    const { count: completed } = await supabase
      .from('emails')
      .select('id', { count: 'exact' })
      .eq('user_id', userId)
      .eq('status', 'complete')
      .gte('created_at', isoToday.toISOString());

    document.getElementById('processed-count').innerText = processed || 0;
    document.getElementById('completed-count').innerText = completed || 0;
  }

  // Fetch recent AI email replies
  async function loadRecentReplies() {
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
      container.appendChild(d);
    });
  }

  // Set up real-time updates for new emails
  function setupRealtime() {
    supabase
      .channel('emails_channel')
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'emails',
          filter: `user_id=eq.${userId}`
        },
        async (payload) => {
          await loadEmailStats();

          const e = payload.new;
          if (e.status !== 'complete') return;

          const container = document.getElementById('activity-container');
          const d = document.createElement('div');
          d.className = 'activity-item';
          d.innerHTML = `
            <div class="activity-header">
              <div class="activity-contact">${e.sender_email}</div>
              <div class="activity-time">${new Date(e.created_at).toLocaleString()}</div>
            </div>
            <div class="activity-content">${e.ai_response}</div>
            <div class="activity-actions">
              <button class="action-btn"><i class="fas fa-eye"></i>Review</button>
              <button class="action-btn"><i class="fas fa-copy"></i>Template</button>
            </div>`;
          container.prepend(d);
        }
      )
      .subscribe();
  }

  // Init dashboard functions
  await loadEmailStats();
  await loadRecentReplies();
  setupRealtime();
}
