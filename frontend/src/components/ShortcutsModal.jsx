import React from 'react'
import { useConsoleStore } from '../store/useConsoleStore'

export default function ShortcutsModal() {
  const { setOverlay } = useConsoleStore()

  const shortcuts = [
    { key: 'SPACE', action: 'Play / Pause Traffic Timeline Replay' },
    { key: '[  /  ]', action: 'Cycle Replay Playback Speed (1x / 4x / 16x)' },
    { key: '/', action: 'Focus Host IP Search Filter' },
    { key: 'ESC', action: 'Close Active Panel / Host Dossier' },
    { key: 'D', action: 'Open Ingest Source & Sensitivity Sliders' },
    { key: 'M', action: 'Open Model Evaluation & Architecture Card' },
    { key: 'R', action: 'Open Incident Report Generator' },
    { key: 'G', action: 'Reset Topology Network Graph Zoom' },
    { key: '?', action: 'Toggle Keyboard Shortcuts Reference Sheet' },
  ]

  return (
    <div className="fixed inset-0 bg-black/85 z-50 flex items-center justify-center p-6 select-none animate-in fade-in duration-100">
      <div className="w-full max-w-lg bg-panel border border-line shadow-2xl flex flex-col">
        {/* Header */}
        <div className="p-3 border-b border-line bg-bg flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="font-condensed font-bold tracking-wider text-base uppercase text-text">
              KEYBOARD SHORTCUTS REFERENCE
            </span>
          </div>
          <button
            onClick={() => setOverlay(null)}
            className="px-2 py-0.5 text-xs font-mono border border-line text-dim hover:text-text uppercase"
          >
            ESC [CLOSE]
          </button>
        </div>

        {/* List */}
        <div className="p-4 space-y-2 text-xs font-mono">
          {shortcuts.map((sc) => (
            <div
              key={sc.key}
              className="flex items-center justify-between p-2 bg-bg border border-line/60"
            >
              <span className="text-dim">{sc.action}</span>
              <kbd className="px-2 py-0.5 bg-line text-text font-bold border border-dim text-2xs">
                {sc.key}
              </kbd>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="p-2 border-t border-line bg-bg text-2xs font-mono text-dim text-center">
          PRESS ANY ASSOCIATED KEY TO TRIGGER SOC ACTION INSTANTLY
        </div>
      </div>
    </div>
  )
}
