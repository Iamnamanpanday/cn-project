import React, { useState, useEffect } from 'react'
import { useConsoleStore } from '../store/useConsoleStore'

export default function BootSequence() {
  const { booting, dismissBoot, data } = useConsoleStore()
  const [lines, setLines] = useState([])

  const totalFlows = data?.summary?.total ?? 9544

  useEffect(() => {
    // If reduced motion preferred, dismiss immediately
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      dismissBoot()
      return
    }

    const bootMessages = [
      '[BOOT:001] INITIALIZING SIGINT ENGINE SUBSYSTEMS...',
      '[BOOT:002] RANDOM FOREST SUPERVISED CLASSIFIER (200 TREES)... OK',
      '[BOOT:003] RECONSTRUCTION MLP AUTOENCODER (16-6-16 ARCHITECTURE)... OK',
      '[BOOT:004] BENIGN REFERENCE DISTRIBUTIONS (4,536 FLOWS)... OK',
      `[BOOT:005] TELEMETRY INGEST FABRIC SYNCHRONIZED... ${totalFlows.toLocaleString()} FLOWS`,
      '[BOOT:006] SOC CONSOLE INSTRUMENT PANEL READY.',
    ]

    let current = 0
    const interval = setInterval(() => {
      if (current < bootMessages.length) {
        setLines((prev) => [...prev, bootMessages[current]])
        current++
      } else {
        clearInterval(interval)
        setTimeout(() => {
          dismissBoot()
        }, 300)
      }
    }, 180)

    return () => clearInterval(interval)
  }, [dismissBoot, totalFlows])

  if (!booting) return null

  return (
    <div className="fixed inset-0 bg-black z-50 flex items-center justify-center p-6 select-none font-mono text-xs">
      <div className="w-full max-w-lg bg-panel border border-line p-6 shadow-2xl space-y-2">
        <div className="flex items-center justify-between pb-2 border-b border-line text-2xs text-dim">
          <span>SIGINT // HARDWARE INITIALIZATION</span>
          <span>SYSTEM_BOOT_V2.4</span>
        </div>
        <div className="space-y-1.5 py-2 min-h-[140px]">
          {lines.map((l, idx) => (
            <div key={idx} className="text-text flex items-center gap-2">
              <span className="w-1.5 h-1.5 bg-ok inline-block shrink-0"></span>
              <span>{l}</span>
            </div>
          ))}
        </div>
        <div className="pt-2 border-t border-line/60 flex justify-between text-2xs text-dim">
          <span>LOADING INSTRUMENT PANEL...</span>
          <button
            onClick={dismissBoot}
            className="hover:text-text underline cursor-pointer"
          >
            SKIP [ESC]
          </button>
        </div>
      </div>
    </div>
  )
}
