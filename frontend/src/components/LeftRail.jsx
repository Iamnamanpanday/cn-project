import React, { useRef, useEffect } from 'react'
import { useConsoleStore } from '../store/useConsoleStore'

function TinySparkline({ data, isInfected }) {
  if (!data || data.length === 0) {
    return <div className="w-12 h-3 bg-line/30" />
  }

  const maxVal = Math.max(...data, 1)
  const width = 48
  const height = 12
  const barWidth = 3
  const gap = 1

  return (
    <svg width={width} height={height} className="shrink-0 overflow-hidden">
      {data.map((val, idx) => {
        const barHeight = Math.max(1, Math.round((val / maxVal) * height))
        const x = idx * (barWidth + gap)
        const y = height - barHeight
        const fill = isInfected && val > 0 ? '#ff3b30' : val > 0 ? '#d9a441' : '#1b2326'
        return <rect key={idx} x={x} y={y} width={barWidth} height={barHeight} fill={fill} />
      })}
    </svg>
  )
}

export default function LeftRail() {
  const {
    data,
    selectedHostIp,
    selectHost,
    hostSearchQuery,
    setHostSearchQuery,
    quarantinedHosts,
  } = useConsoleStore()

  const searchInputRef = useRef(null)

  // Focus search input when '/' is pressed
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === '/' && document.activeElement !== searchInputRef.current) {
        e.preventDefault()
        searchInputRef.current?.focus()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [])

  const devices = data?.devices || []
  const infectedTotal = devices.filter((d) => d.status === 'INFECTED').length

  const filteredDevices = devices.filter((d) =>
    d.src_ip.toLowerCase().includes(hostSearchQuery.toLowerCase())
  )

  return (
    <aside className="w-[300px] h-full bg-panel border-r border-line flex flex-col shrink-0 select-none">
      {/* Rail Header */}
      <div className="p-2 border-b border-line bg-bg flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <span className="font-condensed font-bold tracking-wider text-sm uppercase text-text">
            HOSTS
          </span>
          <span className="text-2xs font-mono text-dim">
            [{infectedTotal}/{devices.length} COMPROMISED]
          </span>
        </div>
        <span className="text-2xs text-dim font-mono">SORT: RISK</span>
      </div>

      {/* Host Search Box */}
      <div className="p-2 border-b border-line bg-panel">
        <div className="relative flex items-center">
          <input
            ref={searchInputRef}
            type="text"
            placeholder="FILTER HOST IP... [/]"
            value={hostSearchQuery}
            onChange={(e) => setHostSearchQuery(e.target.value)}
            className="w-full bg-bg border border-line px-2 py-1 text-xs text-text placeholder-dim/70 font-mono outline-none focus:border-dim"
          />
          {hostSearchQuery && (
            <button
              onClick={() => setHostSearchQuery('')}
              className="absolute right-2 text-2xs text-dim hover:text-text font-mono"
            >
              ESC
            </button>
          )}
        </div>
      </div>

      {/* Dense Host List */}
      <div className="flex-1 overflow-y-auto divide-y divide-line/60">
        {filteredDevices.length === 0 ? (
          <div className="p-4 text-center text-dim text-xs font-mono">
            NO HOSTS MATCHING QUERY
          </div>
        ) : (
          filteredDevices.map((dev) => {
            const isSelected = selectedHostIp === dev.src_ip
            const isInfected = dev.status === 'INFECTED'
            const isQuarantined = quarantinedHosts.includes(dev.src_ip)
            const riskPct = Math.min(100, Math.max(0, dev.flagged_pct))

            return (
              <div
                key={dev.src_ip}
                onClick={() => selectHost(dev.src_ip)}
                className={`p-2 cursor-pointer transition-colors ${
                  isSelected
                    ? 'bg-line/70 border-l-2 border-text'
                    : 'hover:bg-line/30 border-l-2 border-transparent'
                }`}
              >
                {/* Top Row: IP + Status Tag */}
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-1.5 font-mono text-xs">
                    {isInfected && (
                      <span className="w-1.5 h-1.5 bg-threat inline-block"></span>
                    )}
                    <span className={isInfected ? 'text-threat font-bold' : 'text-text'}>
                      {dev.src_ip}
                    </span>
                  </div>

                  <div className="flex items-center gap-1">
                    {isQuarantined && (
                      <span className="text-2xs px-1 bg-threat-dim border border-threat text-threat font-condensed uppercase tracking-wider">
                        ISOLATED
                      </span>
                    )}
                    <span
                      className={`text-2xs px-1 font-condensed tracking-wider font-bold uppercase border ${
                        isInfected
                          ? 'border-threat text-threat bg-threat-dim'
                          : 'border-line text-dim bg-bg'
                      }`}
                    >
                      {dev.status}
                    </span>
                  </div>
                </div>

                {/* Middle Row: Metrics & Sparkline */}
                <div className="flex items-center justify-between text-2xs text-dim font-mono mb-1.5">
                  <div className="flex items-center gap-2">
                    <span>
                      FLAGGED:{' '}
                      <span className={isInfected ? 'text-threat font-bold' : 'text-text'}>
                        {dev.flagged}/{dev.flows}
                      </span>
                    </span>
                    <span>
                      DSTS: <span className="text-text">{dev.unique_dsts}</span>
                    </span>
                  </div>
                  <TinySparkline data={dev.sparkline} isInfected={isInfected} />
                </div>

                {/* Bottom Row: Thin Risk Bar */}
                <div className="w-full bg-bg h-1 border border-line/40 overflow-hidden flex">
                  <div
                    className={`h-full ${
                      isInfected ? 'bg-threat' : riskPct > 10 ? 'bg-warn' : 'bg-dim'
                    }`}
                    style={{ width: `${riskPct}%` }}
                  />
                </div>
              </div>
            )
          })
        )}
      </div>

      {/* Rail Footer */}
      <div className="p-1.5 border-t border-line bg-bg text-2xs text-dim font-mono flex items-center justify-between">
        <span>TOTAL: {devices.length} DEVICES</span>
        <span>SELECT HOST FOR DOSSIER</span>
      </div>
    </aside>
  )
}
