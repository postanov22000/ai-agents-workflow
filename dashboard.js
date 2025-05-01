import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js/+esm';

const supabase = createClient('https://YOUR_PROJECT.supabase.co', 'YOUR_PUBLIC_ANON_KEY');

// Get user
const { data: { user }, error } = await supabase.auth.getUser();
if (!user || error) window.location.href = 'signup.html';
const userId = user.id;

// Get today's date in ISO
const isoToday = new Date();
isoToday.setUTCHours(0, 0, 0, 0);

// Fetch stats
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

// Fetch recent replies
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

  recent.forEach(email => {
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

// Realtime updates
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
        await loadEmailStats(); // refresh stats

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

// Init
await loadEmailStats();
await loadRecentReplies();
setupRealtime();
