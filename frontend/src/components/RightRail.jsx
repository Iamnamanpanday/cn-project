import React, { useMemo, useRef, useEffect } from 'react'
import { useConsoleStore } from '../store/useConsoleStore'

export default function RightRail() {
  const {
    data,
    currentTimeIndex,
    maxTimeIndex,
    eventFilter,
    setEventFilter,
    simulatedLogs,
  } = useConsoleStore()

  const listRef = useRef(null)

  // Filter events based on scrubber time index and filter button
  const displayedEvents = useMemo(() => {
    const rawEvents = data?.events || []
    const timeline = data?.timeline || []

    // Determine the end flow boundary for the current time index
    let currentFlowLimit = rawEvents.length
    if (timeline.length > 0 && currentTimeIndex < timeline.length) {
      currentFlowLimit = timeline[currentTimeIndex]?.end_flow ?? rawEvents.length
    }

    // Slice flows up to current scrubber limit
    const timeSliced = rawEvents.slice(0, currentFlowLimit)

    // Filter by level
    const filtered = timeSliced.filter((ev) => {
      if (eventFilter === 'ALL') return true
      if (eventFilter === 'ALERTS') return ev.is_botnet
      if (eventFilter === 'KNOWN') return ev.reason?.includes('known')
      if (eventFilter === 'ANOMALY') return ev.reason?.includes('anomaly')
      if (eventFilter === 'NORMAL') return !ev.is_botnet
      return true
    })

    // Combine with simulated logs
    const combined = [...simulatedLogs, ...filtered]

    // Newest on top
    return combined.slice(-200).reverse()
  }, [data, currentTimeIndex, eventFilter, simulatedLogs])

  return (
    <aside className="w-[340px] h-full bg-panel border-l border-line flex flex-col shrink-0 select-none">
      {/* Rail Header */}
      <div className="p-2 border-b border-line bg-bg flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <span className="font-condensed font-bold tracking-wider text-sm uppercase text-text">
            EVENT STREAM
          </span>
          <span className="text-2xs font-mono text-dim">
            [{displayedEvents.length} FLOWS]
          </span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 bg-ok"></span>
          <span className="text-2xs font-mono text-dim">FEED: SYNC</span>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="p-1 border-b border-line bg-panel flex items-center gap-1 text-2xs font-condensed uppercase tracking-wider">
        {['ALL', 'ALERTS', 'KNOWN', 'ANOMALY', 'NORMAL'].map((f) => (
          <button
            key={f}
            onClick={() => setEventFilter(f)}
            className={`px-1.5 py-0.5 border ${
              eventFilter === f
                ? 'bg-line border-text text-text font-bold'
                : 'bg-bg border-line text-dim hover:text-text'
            }`}
          >
            {f}
          </button>
        ))}
      </div>

      {/* Terminal Log Output (Newest on top) */}
      <div
        ref={listRef}
        className="flex-1 overflow-y-auto p-2 font-mono text-2xs space-y-1 bg-bg/60 select-text"
      >
        {displayedEvents.length === 0 ? (
          <div className="p-4 text-center text-dim font-mono text-xs">
            NO TELEMETRY EVENTS IN CURRENT WINDOW
          </div>
        ) : (
          displayedEvents.map((ev, i) => {
            // Simulated quarantine log entry
            if (ev.is_simulated) {
              return (
                <div
                  key={`sim-${ev.id || i}`}
                  className="p-1.5 bg-threat-dim/60 border border-threat text-threat"
                >
                  <span className="text-dim mr-1.5">{ev.timestamp}</span>
                  <span className="font-bold mr-1.5 px-1 bg-threat text-black">
                    SIM_QUARANTINE
                  </span>
                  <span>{ev.log_text}</span>
                </div>
              )
            }

            const isAlert = ev.is_botnet
            const reasonTag = ev.reason?.includes('anomaly')
              ? 'ANOMALY'
              : ev.reason?.includes('known')
              ? 'KNOWN'
              : 'NORMAL'

            return (
              <div
                key={`ev-${ev.id || i}`}
                className="leading-tight py-0.5 border-b border-line/20 hover:bg-line/20"
              >
                <span className="text-dim mr-1.5">{ev.timestamp}</span>

                {/* Severity word ONLY gets color */}
                {isAlert ? (
                  <span className="text-threat font-bold mr-1.5">ALERT</span>
                ) : (
                  <span className="text-dim mr-1.5">INFO</span>
                )}

                <span className="text-text">
                  {ev.src_ip} <span className="text-dim">-&gt;</span> {ev.dst_ip}:{ev.dst_port}
                </span>

                <span className="text-dim ml-1.5">
                  [{reasonTag} rf={ev.rf_prob?.toFixed(2)} ae={ev.ae_error?.toFixed(2)}]
                </span>
              </div>
            )
          })
        )}
      </div>

      {/* Rail Footer */}
      <div className="p-1.5 border-t border-line bg-bg text-2xs text-dim font-mono flex items-center justify-between">
        <span>NEWEST EVENTS ON TOP</span>
        <span>DRIVEN BY TIMELINE</span>
      </div>
    </aside>
  )
}
