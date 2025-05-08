import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js/+esm'

const supabaseUrl = document.querySelector('meta[name="supabase-url"]').content
const supabaseAnonKey = document.querySelector('meta[name="supabase-anon-key"]').content
const API_BASE = 'https://replyzeai.onrender.com'

const supabase = createClient(supabaseUrl, supabaseAnonKey)
let userId = null
let realtimeChannel = null

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
}

// Toast System
const showToast = (message, isError = true) => {
  const toast = document.createElement('div')
  toast.className = `toast ${isError ? 'error' : 'success'}`
  toast.textContent = message
  document.body.appendChild(toast)
  setTimeout(() => toast.remove(), 5000)
}

// Format date with error handling
const formatDate = (isoString) => {
  try {
    const date = new Date(isoString)
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  } catch {
    return 'Invalid date'
  }
}

// Enhanced fetch wrapper
const fetchAPI = async (endpoint) => {
  try {
    const { data: { session }, error: authError } = await supabase.auth.getSession()
    
    if (authError || !session?.access_token) {
      showToast('Session expired. Redirecting to login...')
      setTimeout(() => window.location.href = '/login', 2000)
      return null
    }

    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 10000)

    const response = await fetch(`${API_BASE}${endpoint}`, {
      headers: {
        'Authorization': `Bearer ${session.access_token}`,
        'Content-Type': 'application/json'
      },
      signal: controller.signal
    })

    clearTimeout(timeout)

    if (!response.ok) {
      const errorData = await response.json()
      throw new Error(errorData.error || `HTTP ${response.status}`)
    }

    return await response.json()
  } catch (error) {
    showToast(error.message.includes('aborted') 
      ? 'Request timed out' 
      : error.message.replace('Error: ', ''))
    return null
  }
}

// Metrics Handling
const loadMetrics = async () => {
  try {
    const data = await fetchAPI('/api/metrics')
    if (!data) return

    elements.processedCount.textContent = data.processed?.toLocaleString() || '0'
    elements.timeSaved.textContent = data.time_saved 
      ? `${Math.floor(data.time_saved / 60)}h ${data.time_saved % 60}m` 
      : '0m'
    elements.responseAccuracy.textContent = data.processed > 0 
      ? `${(data.accuracy || 0).toFixed(1)}%` 
      : '—'
  } catch (error) {
    console.error('Metrics load error:', error)
  }
}

// Activity Feed
const renderActivities = (activities) => {
  elements.activityContainer.innerHTML = activities.length > 0
    ? activities.map(activity => `
        <div class="activity-item">
          <div class="activity-header">
            <div class="activity-contact">${activity.sender_email || 'Unknown Sender'}</div>
            <div class="activity-time">${formatDate(activity.created_at)}</div>
          </div>
          <div class="activity-content">
            ${activity.processed_content?.substring(0, 120) || 'No content available'}${activity.processed_content?.length > 120 ? '...' : ''}
          </div>
          <div class="activity-actions">
            <button class="action-btn" data-email-id="${activity.id}">
              <i class="fas fa-eye"></i> Review
            </button>
            <span class="status-badge ${activity.status.replace(' ', '-')}">${activity.status}</span>
          </div>
        </div>
      `).join('')
    : '<div class="activity-item">No recent activities found</div>'
}

const loadActivities = async () => {
  try {
    const data = await fetchAPI('/api/activities')
    if (!data?.activities) return
    
    renderActivities(data.activities)
  } catch (error) {
    console.error('Activities load error:', error)
    elements.activityContainer.innerHTML = `
      <div class="activity-item">
        <div class="activity-content">Failed to load activities</div>
      </div>
    `
  }
}

// Realtime Updates
const setupRealtime = () => {
  if (realtimeChannel) {
    realtimeChannel.unsubscribe()
  }

  realtimeChannel = supabase.channel('emails-channel')
    .on('postgres_changes', {
      event: '*',
      schema: 'public',
      table: 'emails',
      filter: `user_id=eq.${userId}`
    }, (payload) => {
      showToast(`New update: ${payload.eventType}`, false)
      loadMetrics()
      loadActivities()
    })
    .subscribe((status) => {
      elements.responderStatus.textContent = 
        status === 'SUBSCRIBED' ? 'Active' : 'Connection Issues'
    })
}

// Event Handlers
const setupEventListeners = () => {
  // Logout
  elements.logoutBtn.addEventListener('click', async () => {
    const { error } = await supabase.auth.signOut()
    if (error) {
      showToast('Logout failed')
      return
    }
    window.location.href = '/login'
  })

  // Configure Button
  elements.configureBtn.addEventListener('click', () => {
    window.location.href = '/configure'
  })

  // Pause/Resume Responder
  elements.pauseBtn.addEventListener('click', async () => {
    try {
      const { error } = await supabase
        .from('user_settings')
        .update({ responder_enabled: !elements.pauseBtn.classList.contains('paused') })
        .eq('user_id', userId)

      if (error) throw error

      const isPaused = !elements.pauseBtn.classList.contains('paused')
      elements.pauseBtn.classList.toggle('paused')
      elements.pauseBtn.innerHTML = `
        <i class="fas ${isPaused ? 'fa-play' : 'fa-pause'}"></i>
        ${isPaused ? 'Resume' : 'Pause'} Responder
      `
      showToast(`Responder ${isPaused ? 'resumed' : 'paused'}`, false)
    } catch (error) {
      showToast('Failed to update responder status')
    }
  })

  // Activity Item Click
  elements.activityContainer.addEventListener('click', async (e) => {
    const btn = e.target.closest('.action-btn')
    if (!btn) return

    const emailId = btn.dataset.emailId
    try {
      const { data, error } = await supabase
        .from('emails')
        .select('*')
        .eq('id', emailId)
        .single()

      if (error) throw error
      window.open(`/email-detail/${emailId}`, '_blank')
    } catch (error) {
      showToast('Failed to load email details')
    }
  })
}

// Initialize Dashboard
const initDashboard = async () => {
  try {
    const { data: { session }, error } = await supabase.auth.getSession()
    
    if (error || !session?.user) {
      window.location.href = '/login'
      return
    }

    userId = session.user.id
    
    // Load initial data
    await Promise.allSettled([loadMetrics(), loadActivities()])
    
    // Setup realtime
    setupRealtime()
    
    // Setup UI interactions
    setupEventListeners()

    // Update status
    elements.responderStatus.textContent = 'Active'

  } catch (error) {
    showToast('Dashboard initialization failed')
    console.error('Initialization error:', error)
    setTimeout(() => window.location.reload(), 3000)
  }
}

// Start the dashboard
document.addEventListener('DOMContentLoaded', initDashboard)
