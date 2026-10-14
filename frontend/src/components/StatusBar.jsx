import React, { useState, useEffect } from 'react'
import { useConsoleStore } from '../store/useConsoleStore'

export default function StatusBar() {
  const { data, params, setOverlay, activeOverlay } = useConsoleStore()
  const [utcTime, setUtcTime] = useState('')

  useEffect(() => {
    const updateTime = () => {
      const now = new Date()
      const iso = now.toISOString()
      // format YYYY-MM-DD HH:mm:ss UTC
      setUtcTime(`${iso.substring(0, 10)} ${iso.substring(11, 19)} UTC`)
    }
    updateTime()
    const timer = setInterval(updateTime, 1000)
    return () => clearInterval(timer)
  }, [])

  const summary = data?.summary || {}
  const totalFlows = summary.total ?? 0
  const threatLevel = summary.threat_level || 'NOMINAL'
  const infectedCount = summary.infected_devices ?? 0
  const sourceName = summary.source_file || params.sample_name || 'TELEMETRY_FEED'

  // Threat level styles
  const threatBadge = () => {
    if (threatLevel === 'CRITICAL') {
      return (
        <div className="flex items-center gap-2 px-3 py-1 bg-threat-dim border border-threat text-threat font-condensed tracking-wider font-bold text-sm uppercase pulse-threat">
          <span className="inline-block w-2 h-2 bg-threat"></span>
          <span>CRITICAL // {infectedCount} HOST{infectedCount === 1 ? '' : 'S'} COMPROMISED</span>
        </div>
      )
    }
    if (threatLevel === 'ELEVATED') {
      return (
        <div className="flex items-center gap-2 px-3 py-1 bg-panel border border-warn text-warn font-condensed tracking-wider font-bold text-sm uppercase">
          <span className="inline-block w-2 h-2 bg-warn"></span>
          <span>ELEVATED // ANOMALY DETECTED</span>
        </div>
      )
    }
    return (
      <div className="flex items-center gap-2 px-3 py-1 bg-panel border border-ok text-ok font-condensed tracking-wider font-bold text-sm uppercase">
        <span className="inline-block w-2 h-2 bg-ok"></span>
        <span>NOMINAL // CLEAN FABRIC</span>
      </div>
    )
  }

  return (
    <header className="h-10 bg-panel border-b border-line px-3 flex items-center justify-between select-none z-30 shrink-0">
      {/* Left: SOC Identity & Ingest Telemetry */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <div className="w-2.5 h-2.5 bg-ok border border-ok/40"></div>
          <span className="font-condensed font-bold tracking-widest text-base text-text">
            SIGINT // IOT-BOTNET MONITOR
          </span>
          <span className="text-2xs text-dim border border-line px-1 py-0.5 ml-1">
            v2.4-SOC
          </span>
        </div>

        <div className="h-4 w-px bg-line"></div>

        <div className="flex items-center gap-3 text-xs text-dim">
          <span>
            SRC: <span className="text-text font-mono uppercase">{sourceName}</span>
          </span>
          <span>
            FLOWS: <span className="text-text font-mono">{totalFlows.toLocaleString()}</span>
          </span>
          <span>
            MODELS: <span className="text-ok font-mono">RF+AE ONLINE</span>
          </span>
        </div>
      </div>

      {/* Center: Threat Level Status */}
      <div className="flex items-center justify-center">
        {threatBadge()}
      </div>

      {/* Right: Clock & Overlay Triggers */}
      <div className="flex items-center gap-3">
        <div className="text-xs text-dim font-mono tracking-wider">
          {utcTime}
        </div>

        <div className="h-4 w-px bg-line"></div>

        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setOverlay(activeOverlay === 'DATA' ? null : 'DATA')}
            className={`px-2 py-1 text-xs font-condensed tracking-wider uppercase border ${
              activeOverlay === 'DATA'
                ? 'bg-line border-text text-text'
                : 'bg-bg border-line text-dim hover:text-text hover:border-dim'
            }`}
            title="Data Upload & Sensitivity Sliders (Press D)"
          >
            DATA [D]
          </button>

          <button
            onClick={() => setOverlay(activeOverlay === 'MODELS' ? null : 'MODELS')}
            className={`px-2 py-1 text-xs font-condensed tracking-wider uppercase border ${
              activeOverlay === 'MODELS'
                ? 'bg-line border-text text-text'
                : 'bg-bg border-line text-dim hover:text-text hover:border-dim'
            }`}
            title="Model Evaluation Specs (Press M)"
          >
            MODELS [M]
          </button>

          <button
            onClick={() => setOverlay(activeOverlay === 'REPORT' ? null : 'REPORT')}
            className={`px-2 py-1 text-xs font-condensed tracking-wider uppercase border ${
              activeOverlay === 'REPORT'
                ? 'bg-line border-text text-text'
                : 'bg-bg border-line text-dim hover:text-text hover:border-dim'
            }`}
            title="Generate Printable Incident Report (Press R)"
          >
            REPORT [R]
          </button>

          <button
            onClick={() => setOverlay(activeOverlay === 'SHORTCUTS' ? null : 'SHORTCUTS')}
            className={`px-2 py-1 text-xs font-mono border ${
              activeOverlay === 'SHORTCUTS'
                ? 'bg-line border-text text-text'
                : 'bg-bg border-line text-dim hover:text-text hover:border-dim'
            }`}
            title="Keyboard Shortcuts Cheatsheet (Press ?)"
          >
            ?
          </button>
        </div>
      </div>
    </header>
  )
}
