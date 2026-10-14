import React, { useRef, useEffect, useCallback } from 'react'
import { useConsoleStore } from '../store/useConsoleStore'

export default function BottomTimeline() {
  const {
    data,
    isPlaying,
    playbackSpeed,
    currentTimeIndex,
    maxTimeIndex,
    togglePlay,
    setSpeed,
    cycleSpeed,
    setTimeIndex,
    tickPlayback,
  } = useConsoleStore()

  const timelineRef = useRef(null)
  const isDraggingRef = useRef(false)

  // Playback timer driven by speed
  useEffect(() => {
    if (!isPlaying) return
    const intervalMs = playbackSpeed === 16 ? 60 : playbackSpeed === 4 ? 200 : 700
    const timer = setInterval(() => {
      tickPlayback()
    }, intervalMs)
    return () => clearInterval(timer)
  }, [isPlaying, playbackSpeed, tickPlayback])

  const timelineBuckets = data?.timeline || []
  const bucketCount = timelineBuckets.length || 1

  // Find max flow volume in buckets for scaling
  const maxFlowInBucket = Math.max(
    ...timelineBuckets.map((b) => b.flows || 0),
    1
  )

  // Scrub click or drag handler
  const handleScrub = useCallback(
    (e) => {
      if (!timelineRef.current || bucketCount === 0) return
      const rect = timelineRef.current.getBoundingClientRect()
      const clickX = Math.max(0, Math.min(rect.width, e.clientX - rect.x))
      const fraction = clickX / rect.width
      const targetIdx = Math.round(fraction * (bucketCount - 1))
      setTimeIndex(targetIdx)
    },
    [bucketCount, setTimeIndex]
  )

  const handleMouseDown = (e) => {
    isDraggingRef.current = true
    handleScrub(e)
  }

  useEffect(() => {
    const handleMouseMove = (e) => {
      if (isDraggingRef.current) {
        handleScrub(e)
      }
    }
    const handleMouseUp = () => {
      isDraggingRef.current = false
    }
    window.addEventListener('mousemove', handleMouseMove)
    window.addEventListener('mouseup', handleMouseUp)
    return () => {
      window.removeEventListener('mousemove', handleMouseMove)
      window.removeEventListener('mouseup', handleMouseUp)
    }
  }, [handleScrub])

  const currentBucket = timelineBuckets[currentTimeIndex] || timelineBuckets[0] || {}

  return (
    <footer className="h-16 bg-panel border-t border-line flex items-center px-3 select-none z-20 shrink-0">
      {/* Playback Controls & Status */}
      <div className="flex items-center gap-3 pr-4 border-r border-line shrink-0">
        <button
          onClick={togglePlay}
          className={`px-3 py-1 text-xs font-condensed tracking-wider font-bold border uppercase flex items-center gap-1.5 ${
            isPlaying
              ? 'bg-warn text-black border-warn'
              : 'bg-bg text-text border-line hover:border-dim'
          }`}
          title="Play / Pause Replay (Space)"
        >
          {isPlaying ? (
            <>
              <span className="w-2 h-2 bg-black inline-block"></span>
              <span>PAUSE</span>
            </>
          ) : (
            <>
              <span className="inline-block border-y-4 border-y-transparent border-l-6 border-l-text"></span>
              <span>PLAY</span>
            </>
          )}
        </button>

        {/* Speed Switcher */}
        <div className="flex items-center border border-line bg-bg text-2xs font-condensed">
          {[1, 4, 16].map((spd) => (
            <button
              key={spd}
              onClick={() => setSpeed(spd)}
              className={`px-1.5 py-0.5 tracking-wider font-mono ${
                playbackSpeed === spd
                  ? 'bg-line text-text font-bold'
                  : 'text-dim hover:text-text'
              }`}
            >
              {spd}X
            </button>
          ))}
        </div>

        {/* Current Time Bucket Readout */}
        <div className="text-2xs font-mono text-dim leading-tight">
          <div>
            T: <span className="text-text font-bold">{currentBucket.t || 'T+00s'}</span>
          </div>
          <div>
            FL: <span className="text-text">{currentBucket.flows ?? 0}</span> |{' '}
            <span className={currentBucket.flagged > 0 ? 'text-threat font-bold' : 'text-dim'}>
              FLG: {currentBucket.flagged ?? 0}
            </span>
          </div>
        </div>
      </div>

      {/* Hand-Built SVG Histogram Timeline */}
      <div
        ref={timelineRef}
        onMouseDown={handleMouseDown}
        className="flex-1 h-full relative cursor-ew-resize ml-3 flex items-center"
      >
        <svg className="w-full h-11 overflow-visible">
          {/* Subtle horizontal grid lines */}
          <line x1="0" y1="0" x2="100%" y2="0" stroke="#1b2326" strokeWidth="1" />
          <line x1="0" y1="22" x2="100%" y2="22" stroke="#1b2326" strokeWidth="1" strokeDasharray="2,2" />
          <line x1="0" y1="44" x2="100%" y2="44" stroke="#1b2326" strokeWidth="1" />

          {/* Histogram Bars */}
          {timelineBuckets.map((bucket, i) => {
            const count = timelineBuckets.length
            const barWidthPercent = 100 / count
            const xPercent = i * barWidthPercent
            const totalH = Math.max(2, Math.round(((bucket.flows || 0) / maxFlowInBucket) * 40))
            const flaggedH = Math.max(
              bucket.flagged > 0 ? 2 : 0,
              Math.round(((bucket.flagged || 0) / maxFlowInBucket) * 40)
            )

            const isPassed = i <= currentTimeIndex

            return (
              <g key={i}>
                {/* Total Flows Bar */}
                <rect
                  x={`${xPercent + 0.3}%`}
                  y={44 - totalH}
                  width={`${Math.max(0.4, barWidthPercent - 0.6)}%`}
                  height={totalH}
                  fill={isPassed ? '#2b363a' : '#141a1c'}
                />

                {/* Flagged Flows Overlay Bar (Red is reserved for flagged/threats) */}
                {flaggedH > 0 && (
                  <rect
                    x={`${xPercent + 0.3}%`}
                    y={44 - flaggedH}
                    width={`${Math.max(0.4, barWidthPercent - 0.6)}%`}
                    height={flaggedH}
                    fill={isPassed ? '#ff3b30' : '#4a1512'}
                  />
                )}
              </g>
            )
          })}

          {/* Scrubber Playhead Line */}
          {bucketCount > 0 && (
            <g
              transform={`translate(${
                (currentTimeIndex / Math.max(1, bucketCount - 1)) * 100
              }%, 0)`}
            >
              <line
                x1="0"
                y1="0"
                x2="0"
                y2="44"
                stroke="#c7d1cf"
                strokeWidth="2"
              />
              {/* Scrubber Head Diamond */}
              <polygon
                points="0,0 -4,-5 4,-5"
                fill="#c7d1cf"
              />
              <polygon
                points="0,44 -4,49 4,49"
                fill="#c7d1cf"
              />
            </g>
          )}
        </svg>

        {/* Timeline Axis Labels */}
        <div className="absolute -bottom-1 left-0 right-0 flex justify-between text-2xs font-mono text-dim pointer-events-none px-1">
          <span>{timelineBuckets[0]?.t || 'START'}</span>
          <span>SCRUB / REPLAY DRIVES NETWORK GRAPH &amp; TELEMETRY STREAM</span>
          <span>{timelineBuckets[timelineBuckets.length - 1]?.t || 'END'}</span>
        </div>
      </div>
    </footer>
  )
}
