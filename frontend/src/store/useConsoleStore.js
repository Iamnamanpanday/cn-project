import { create } from 'zustand'
import axios from 'axios'

export const useConsoleStore = create((set, get) => ({
  // Active analysis data
  data: null,
  loading: false,
  error: null,
  booting: true,

  // Parameters
  params: {
    rf_threshold: 0.5,
    ae_scale: 1.0,
    cutoff: 30.0,
    min_flows: 5,
    sample_name: 'iot23_small.csv',
  },

  // Active uploaded file (if any)
  activeUploadFile: null,

  // Selected host dossier
  selectedHostIp: null,
  hostExplanation: null,
  explaining: false,

  // Quarantine simulation
  quarantinedHosts: [],
  simulatedLogs: [],

  // Timeline & Playback
  isPlaying: false,
  playbackSpeed: 1, // 1x, 4x, 16x
  currentTimeIndex: 35, // default to all buckets loaded
  maxTimeIndex: 35,

  // Filters & Search
  hostSearchQuery: '',
  eventFilter: 'ALL', // 'ALL' | 'ALERT' | 'NORMAL' | 'KNOWN' | 'ANOMALY'

  // Overlays: null | 'MODELS' | 'REPORT' | 'DATA' | 'SHORTCUTS'
  activeOverlay: null,

  // Available sample test datasets
  availableSamples: [],

  // Actions
  dismissBoot: () => set({ booting: false }),

  setOverlay: (overlay) => set({ activeOverlay: overlay }),

  setHostSearchQuery: (q) => set({ hostSearchQuery: q }),

  setEventFilter: (f) => set({ eventFilter: f }),

  fetchSamples: async () => {
    try {
      const res = await axios.get('/api/samples')
      set({ availableSamples: res.data.samples || [] })
    } catch (e) {
      console.warn('Could not fetch sample list:', e)
    }
  },

  fetchAnalysis: async () => {
    const { params, activeUploadFile } = get()
    set({ loading: true, error: null })
    try {
      let res
      if (activeUploadFile) {
        const formData = new FormData()
        formData.append('file', activeUploadFile)
        res = await axios.post(
          `/api/analyze?rf_threshold=${params.rf_threshold}&ae_scale=${params.ae_scale}&cutoff=${params.cutoff}&min_flows=${params.min_flows}`,
          formData,
          { headers: { 'Content-Type': 'multipart/form-data' } }
        )
      } else {
        res = await axios.get('/api/analyze-sample', {
          params: {
            sample_name: params.sample_name,
            rf_threshold: params.rf_threshold,
            ae_scale: params.ae_scale,
            cutoff: params.cutoff,
            min_flows: params.min_flows,
          },
        })
      }

      const payload = res.data
      const bucketsCount = payload.timeline ? payload.timeline.length : 36
      
      set({
        data: payload,
        loading: false,
        maxTimeIndex: Math.max(0, bucketsCount - 1),
        currentTimeIndex: Math.max(0, bucketsCount - 1), // start at end of time window
      })

      // If currently selected host is still present, update explanation
      const currentSelected = get().selectedHostIp
      if (currentSelected) {
        get().selectHost(currentSelected)
      }
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Failed to analyze traffic'
      set({ error: msg, loading: false })
    }
  },

  setParams: (newParams) => {
    set((state) => ({ params: { ...state.params, ...newParams } }))
    // Debounce re-analysis in component or trigger
  },

  setSample: (sampleName) => {
    set((state) => ({
      activeUploadFile: null,
      params: { ...state.params, sample_name: sampleName },
    }))
    get().fetchAnalysis()
  },

  setUploadFile: (file) => {
    set({ activeUploadFile: file })
    get().fetchAnalysis()
  },

  selectHost: async (ip) => {
    set({ selectedHostIp: ip, explaining: true, hostExplanation: null })
    try {
      const res = await axios.get(`/api/explain/${encodeURIComponent(ip)}`)
      set({ hostExplanation: res.data, explaining: false })
    } catch (err) {
      console.warn(`Explain failed for ${ip}:`, err)
      set({ explaining: false, hostExplanation: null })
    }
  },

  closeHostDossier: () => {
    set({ selectedHostIp: null, hostExplanation: null })
  },

  toggleQuarantine: (ip) => {
    const { quarantinedHosts, simulatedLogs, data } = get()
    const isQuarantined = quarantinedHosts.includes(ip)
    const newQuarantined = isQuarantined
      ? quarantinedHosts.filter((x) => x !== ip)
      : [...quarantinedHosts, ip]

    const timestamp = new Date().toISOString().substring(11, 19) + 'Z'
    const actionText = isQuarantined
      ? `QUARANTINE REMOVED: ${ip} RECONNECTED TO FABRIC (SIMULATION)`
      : `QUARANTINE SIMULATED: ${ip} ISOLATED - FIREWALL DROP RULES ACTIVE`

    const newLog = {
      id: Date.now(),
      timestamp,
      src_ip: ip,
      dst_ip: 'FIREWALL_DROP',
      dst_port: 0,
      rf_prob: 1.0,
      ae_error: 0.0,
      reason: 'SIMULATION',
      is_botnet: true,
      attack_type: 'QUARANTINE_ISOLATION',
      is_simulated: true,
      log_text: actionText,
    }

    set({
      quarantinedHosts: newQuarantined,
      simulatedLogs: [newLog, ...simulatedLogs],
    })
  },

  // Playback controls
  togglePlay: () => {
    set((state) => {
      // If at end, loop to beginning
      const nextTime = state.currentTimeIndex >= state.maxTimeIndex ? 0 : state.currentTimeIndex
      return { isPlaying: !state.isPlaying, currentTimeIndex: nextTime }
    })
  },

  setSpeed: (speed) => set({ playbackSpeed: speed }),

  cycleSpeed: () => {
    const speeds = [1, 4, 16]
    const current = get().playbackSpeed
    const next = speeds[(speeds.indexOf(current) + 1) % speeds.length]
    set({ playbackSpeed: next })
  },

  setTimeIndex: (idx) => {
    const clamped = Math.max(0, Math.min(get().maxTimeIndex, idx))
    set({ currentTimeIndex: clamped })
  },

  tickPlayback: () => {
    const { isPlaying, currentTimeIndex, maxTimeIndex } = get()
    if (!isPlaying) return
    if (currentTimeIndex >= maxTimeIndex) {
      set({ isPlaying: false })
    } else {
      set({ currentTimeIndex: currentTimeIndex + 1 })
    }
  },
}))
