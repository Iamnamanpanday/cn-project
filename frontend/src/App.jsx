import React, { useEffect } from 'react'
import { useConsoleStore } from './store/useConsoleStore'
import StatusBar from './components/StatusBar'
import LeftRail from './components/LeftRail'
import CenterCanvas from './components/CenterCanvas'
import RightRail from './components/RightRail'
import BottomTimeline from './components/BottomTimeline'
import HostDossier from './components/HostDossier'
import ModelsOverlay from './components/ModelsOverlay'
import ReportOverlay from './components/ReportOverlay'
import DataOverlay from './components/DataOverlay'
import ShortcutsModal from './components/ShortcutsModal'
import BootSequence from './components/BootSequence'

export default function App() {
  const {
    fetchAnalysis,
    fetchSamples,
    activeOverlay,
    setOverlay,
    selectedHostIp,
    closeHostDossier,
    togglePlay,
    cycleSpeed,
    error,
    loading,
  } = useConsoleStore()

  // Initial data and samples fetch
  useEffect(() => {
    fetchSamples()
    fetchAnalysis()
  }, [fetchSamples, fetchAnalysis])

  // Global keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Ignore if user is typing in an input
      if (['INPUT', 'TEXTAREA'].includes(e.target.tagName)) {
        if (e.key === 'Escape') {
          e.target.blur()
        }
        return
      }

      if (e.key === 'Escape') {
        if (activeOverlay) {
          setOverlay(null)
        } else if (selectedHostIp) {
          closeHostDossier()
        }
        return
      }

      if (e.code === 'Space') {
        e.preventDefault()
        togglePlay()
        return
      }

      if (e.key === '[' || e.key === ']') {
        e.preventDefault()
        cycleSpeed()
        return
      }

      if (e.key === '?' || (e.shiftKey && e.key === '/')) {
        e.preventDefault()
        setOverlay(activeOverlay === 'SHORTCUTS' ? null : 'SHORTCUTS')
        return
      }

      if (e.key === 'd' || e.key === 'D') {
        setOverlay(activeOverlay === 'DATA' ? null : 'DATA')
        return
      }

      if (e.key === 'm' || e.key === 'M') {
        setOverlay(activeOverlay === 'MODELS' ? null : 'MODELS')
        return
      }

      if (e.key === 'r' || e.key === 'R') {
        setOverlay(activeOverlay === 'REPORT' ? null : 'REPORT')
        return
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [activeOverlay, selectedHostIp, setOverlay, closeHostDossier, togglePlay, cycleSpeed])

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-bg text-text select-none">
      {/* 1.2s Real Boot Sequence */}
      <BootSequence />

      {/* Top Status Bar */}
      <StatusBar />

      {/* Main Single-Screen SOC Console Area (Left Rail + Center Topology + Right Feed) */}
      <div className="flex flex-1 overflow-hidden relative">
        {/* Left: Dense Host Risk Table */}
        <LeftRail />

        {/* Center: Network Topology Force Canvas */}
        <CenterCanvas />

        {/* Right: Live Telemetry Event Stream Feed */}
        <RightRail />

        {/* Host Dossier (Slide-in right panel) */}
        <HostDossier />
      </div>

      {/* Bottom Timeline Histogram & Replay Scrubber */}
      <BottomTimeline />

      {/* Overlays */}
      {activeOverlay === 'MODELS' && <ModelsOverlay />}
      {activeOverlay === 'REPORT' && <ReportOverlay />}
      {activeOverlay === 'DATA' && <DataOverlay />}
      {activeOverlay === 'SHORTCUTS' && <ShortcutsModal />}

      {/* Error State Banner if needed */}
      {error && (
        <div className="absolute top-12 left-1/2 -translate-x-1/2 bg-threat-dim border border-threat text-threat px-4 py-2 font-mono text-xs z-50 flex items-center gap-3 shadow-2xl">
          <span className="font-bold">TELEMETRY ERROR: {error}</span>
          <button
            onClick={() => fetchAnalysis()}
            className="px-2 py-0.5 bg-threat text-black font-bold uppercase text-2xs"
          >
            RETRY
          </button>
        </div>
      )}

      {/* Subtle Loading indicator in corner */}
      {loading && (
        <div className="absolute bottom-20 right-4 bg-panel border border-line px-2 py-1 text-2xs font-mono text-dim z-30 pointer-events-none">
          RE-ANALYZING FLOWS...
        </div>
      )}
    </div>
  )
}
