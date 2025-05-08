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

// Network Utilities
const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms))

const formatDate = (isoString) => {
  try {
    return new Date(isoString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  } catch {
    return 'Invalid date'
  }
}

// Enhanced Fetch with Retry
const fetchAPI = async (endpoint, retries = 3) => {
  for (let i = 0; i < retries; i++) {
    try {
      const { data: { session }, error: authError } = await supabase.auth.getSession()
      
      if (authError || !session?.access_token) {
        showToast('Session expired. Redirecting...')
        await wait(2000)
        window.location.href = '/login'
        return null
      }

      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), 8000)

      const response = await fetch(`${API_BASE}${endpoint}`, {
        headers: {
          'Authorization': `Bearer ${session.access_token}`,
          'Content-Type': 'application/json'
        },
        signal: controller.signal,
        credentials: 'include'
      })

      clearTimeout(timeoutId)

      if (response.status === 401) {
        showToast('Session expired. Redirecting...')
        await wait(2000)
        window.location.href = '/login'
        return null
      }

      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(`HTTP ${response.status}: ${errorText.slice(0, 100)}`)
      }

      return await response.json()
    } catch (error) {
      if (i === retries - 1) {
        showToast(error.name === 'AbortError' ? 'Request timed out' : error.message)
        throw error
      }
      await wait(2000 * (i + 1))
    }
  }
}

// Data Loading
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
    console.error('Metrics load failed:', error)
  }
}

const renderActivities = (activities) => {
  elements.activityContainer.innerHTML = activities.length > 0
    ? activities.map(activity => `
        <div class="activity-item">
          <div class="activity-header">
            <div class="activity-contact">${activity.sender_email || 'Unknown'}</div>
            <div class="activity-time">${formatDate(activity.created_at)}</div>
          </div>
          <div class="activity-content">
            ${(activity.processed_content || 'No content').substring(0, 120)}${activity.processed_content?.length > 120 ? '...' : ''}
          </div>
          <div class="activity-actions">
            <button class="action-btn" data-email-id="${activity.id}">
              <i class="fas fa-eye"></i> Review
            </button>
            <span class="status-badge ${activity.status.replace(/_/g, '-')}">
              ${activity.status.replace(/_/g, ' ')}
            </span>
          </div>
        </div>
      `).join('')
    : '<div class="activity-item">No recent activities</div>'
}

const loadActivities = async () => {
  try {
    const data = await fetchAPI('/api/activities')
    if (!data?.activities) return
    
    renderActivities(data.activities)
  } catch (error) {
    console.error('Activities load failed:', error)
    elements.activityContainer.innerHTML = `
      <div class="activity-item error">
        Failed to load activities. ${error.message}
      </div>
    `
  }
}

// Real-time Updates
const setupRealtime = () => {
  if (realtimeChannel) {
    realtimeChannel.unsubscribe().catch(console.error)
  }

  realtimeChannel = supabase.channel('email-updates')
    .on('postgres_changes', {
      event: '*',
      schema: 'public',
      table: 'emails',
      filter: `user_id=eq.${userId}`
    }, async (payload) => {
      showToast(`New update: ${payload.eventType}`, false)
      await Promise.allSettled([loadMetrics(), loadActivities()])
    })
    .subscribe((status) => {
      elements.responderStatus.textContent = 
        status === 'SUBSCRIBED' ? 'Active' : 'Connection Issues'
    })
}

// Event Handlers
const setupEventListeners = () => {
  elements.logoutBtn.addEventListener('click', async () => {
    try {
      const { error } = await supabase.auth.signOut()
      if (error) throw error
      window.location.href = '/login'
    } catch (error) {
      showToast('Logout failed. Please try again.')
    }
  })

  elements.configureBtn.addEventListener('click', () => {
    window.location.href = '/configure'
  })

  elements.pauseBtn.addEventListener('click', async () => {
    try {
      const { error } = await supabase
        .from('user_settings')
        .update({ responder_enabled: !elements.pauseBtn.classList.contains('paused') })
        .eq('user_id', userId)

      if (error) throw error

      elements.pauseBtn.classList.toggle('paused')
      const isPaused = elements.pauseBtn.classList.contains('paused')
      elements.pauseBtn.innerHTML = `
        <i class="fas ${isPaused ? 'fa-play' : 'fa-pause'}"></i>
        ${isPaused ? 'Resume' : 'Pause'} Responder
      `
      showToast(`Responder ${isPaused ? 'paused' : 'resumed'}`, false)
    } catch (error) {
      showToast('Failed to update responder status')
    }
  })

  elements.activityContainer.addEventListener('click', async (e) => {
    const btn = e.target.closest('.action-btn')
    if (!btn) return

    try {
      const { data, error } = await supabase
        .from('emails')
        .select('*')
        .eq('id', btn.dataset.emailId)
        .single()

      if (error) throw error
      window.open(`/email-detail/${btn.dataset.emailId}`, '_blank')
    } catch (error) {
      showToast('Failed to load email details')
    }
  })
}

// Initialization
const initializeDashboard = async () => {
  try {
    const { data: { session }, error } = await supabase.auth.getSession()
    
    if (error || !session?.user) {
      window.location.href = '/login'
      return
    }

    userId = session.user.id

    // Verify database connection
    const { error: dbError } = await supabase
      .from('emails')
      .select('id')
      .limit(1)
    
    if (dbError) throw dbError

    // Load initial data
    await Promise.allSettled([loadMetrics(), loadActivities()])
    setupRealtime()
    setupEventListeners()

    elements.responderStatus.textContent = 'Active'
    showToast('Dashboard loaded successfully', false)

  } catch (error) {
    console.error('Initialization error:', error)
    showToast(`Initialization failed: ${error.message}`)
    setTimeout(() => window.location.reload(), 5000)
  }
}

// Start the dashboard
document.addEventListener('DOMContentLoaded', initializeDashboard)
