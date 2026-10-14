import React, { useRef, useState, useEffect } from 'react'
import { useConsoleStore } from '../store/useConsoleStore'

export default function DataOverlay() {
  const {
    params,
    setParams,
    setSample,
    setUploadFile,
    fetchAnalysis,
    setOverlay,
    availableSamples,
    activeUploadFile,
  } = useConsoleStore()

  const [localParams, setLocalParams] = useState(params)
  const [dragActive, setDragActive] = useState(false)
  const fileInputRef = useRef(null)

  // Keep local params in sync
  useEffect(() => {
    setLocalParams(params)
  }, [params])

  // Debounce slider adjustments by 300ms
  useEffect(() => {
    const handler = setTimeout(() => {
      if (
        localParams.rf_threshold !== params.rf_threshold ||
        localParams.ae_scale !== params.ae_scale ||
        localParams.cutoff !== params.cutoff ||
        localParams.min_flows !== params.min_flows
      ) {
        setParams(localParams)
        fetchAnalysis()
      }
    }, 300)
    return () => clearTimeout(handler)
  }, [localParams, params, setParams, fetchAnalysis])

  const handleSliderChange = (key, value) => {
    setLocalParams((prev) => ({ ...prev, [key]: Number(value) }))
  }

  const handleFileDrop = (e) => {
    e.preventDefault()
    setDragActive(false)
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setUploadFile(e.dataTransfer.files[0])
    }
  }

  const handleFileInput = (e) => {
    if (e.target.files && e.target.files[0]) {
      setUploadFile(e.target.files[0])
    }
  }

  return (
    <div className="fixed inset-0 bg-black/85 z-50 flex items-center justify-center p-6 select-none animate-in fade-in duration-100">
      <div className="w-full max-w-3xl bg-panel border border-line flex flex-col max-h-[90vh] shadow-2xl">
        {/* Header */}
        <div className="p-3 border-b border-line bg-bg flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="font-condensed font-bold tracking-wider text-base uppercase text-text">
              INGEST SOURCE &amp; DETECTION SENSITIVITY CONFIG
            </span>
            <span className="text-2xs font-mono text-dim">[REAL-TIME TUNING]</span>
          </div>
          <button
            onClick={() => setOverlay(null)}
            className="px-2 py-0.5 text-xs font-mono border border-line text-dim hover:text-text uppercase"
          >
            ESC [CLOSE]
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-5 space-y-6">
          {/* Section 1: Built-in Datasets & Test Sets */}
          <div>
            <h2 className="text-xs font-condensed font-bold uppercase tracking-wider text-text mb-2">
              SELECT BUILT-IN CAPTURE OR TEST SET
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {availableSamples.map((s) => {
                const isActive = !activeUploadFile && params.sample_name === s.name
                return (
                  <button
                    key={s.name}
                    onClick={() => setSample(s.name)}
                    className={`p-2.5 text-left border flex flex-col justify-between transition-colors ${
                      isActive
                        ? 'border-ok bg-ok/10 text-text'
                        : 'border-line bg-bg hover:border-dim text-dim hover:text-text'
                    }`}
                  >
                    <div className="flex items-center justify-between font-mono text-xs mb-1">
                      <span className="font-bold text-text">{s.name}</span>
                      <span className="text-2xs px-1 border border-line">{s.category}</span>
                    </div>
                    <div className="text-2xs text-dim mb-1">{s.desc}</div>
                    <div className="text-2xs font-mono text-ok">EXPECTED: {s.expected}</div>
                  </button>
                )
              })}
            </div>
          </div>

          {/* Section 2: Upload Custom CSV */}
          <div>
            <h2 className="text-xs font-condensed font-bold uppercase tracking-wider text-text mb-2">
              UPLOAD CUSTOM CSV // PROCESSED OR RAW ZEEK CONN.LOG.LABELED
            </h2>
            <div
              onDragOver={(e) => {
                e.preventDefault()
                setDragActive(true)
              }}
              onDragLeave={() => setDragActive(false)}
              onDrop={handleFileDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`p-6 border-2 border-dashed text-center cursor-pointer transition-colors ${
                dragActive
                  ? 'border-ok bg-ok/10'
                  : 'border-line bg-bg hover:border-dim'
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".csv"
                onChange={handleFileInput}
                className="hidden"
              />
              <div className="text-xs font-mono text-text uppercase mb-1">
                DRAG AND DROP TELEMETRY CSV HERE, OR CLICK TO BROWSE
              </div>
              <div className="text-2xs font-mono text-dim">
                {activeUploadFile ? (
                  <span className="text-ok font-bold">
                    ACTIVE UPLOAD: {activeUploadFile.name} ({(activeUploadFile.size / 1024).toFixed(1)} KB)
                  </span>
                ) : (
                  'Supports pre-extracted feature sets (REAL_FEATURES) or standard Zeek conn.log.labeled CSVs'
                )}
              </div>
            </div>
          </div>

          {/* Section 3: Sensitivity Sliders (Debounced 300ms) */}
          <div className="border border-line bg-bg p-4 space-y-4">
            <div className="flex items-center justify-between border-b border-line pb-2">
              <h2 className="text-xs font-condensed font-bold uppercase tracking-wider text-text">
                DETECTION HYPERPARAMETERS &amp; INFECTION THRESHOLDS
              </h2>
              <span className="text-2xs font-mono text-dim">DEBOUNCED: 300MS LIVE RE-ANALYSIS</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs font-mono">
              {/* Slider 1: Random Forest Threshold */}
              <div>
                <div className="flex justify-between mb-1">
                  <span className="text-dim">RANDOM FOREST THRESHOLD:</span>
                  <span className="text-text font-bold">{localParams.rf_threshold.toFixed(2)}</span>
                </div>
                <input
                  type="range"
                  min="0.10"
                  max="0.90"
                  step="0.05"
                  value={localParams.rf_threshold}
                  onChange={(e) => handleSliderChange('rf_threshold', e.target.value)}
                  className="w-full accent-text cursor-pointer"
                />
                <div className="text-2xs text-dim mt-0.5">
                  Probability threshold for supervised classification (default: 0.50).
                </div>
              </div>

              {/* Slider 2: Autoencoder Tolerance Scale */}
              <div>
                <div className="flex justify-between mb-1">
                  <span className="text-dim">AUTOENCODER TOLERANCE SCALE:</span>
                  <span className="text-text font-bold">{localParams.ae_scale.toFixed(1)}x</span>
                </div>
                <input
                  type="range"
                  min="1.0"
                  max="3.0"
                  step="0.1"
                  value={localParams.ae_scale}
                  onChange={(e) => handleSliderChange('ae_scale', e.target.value)}
                  className="w-full accent-text cursor-pointer"
                />
                <div className="text-2xs text-dim mt-0.5">
                  Higher scale reduces false positives on noisy benign flows (default: 1.0x).
                </div>
              </div>

              {/* Slider 3: Device Infection Cutoff % */}
              <div>
                <div className="flex justify-between mb-1">
                  <span className="text-dim">DEVICE INFECTED IF FLAGGED &gt;</span>
                  <span className="text-text font-bold">{localParams.cutoff}%</span>
                </div>
                <input
                  type="range"
                  min="5"
                  max="95"
                  step="5"
                  value={localParams.cutoff}
                  onChange={(e) => handleSliderChange('cutoff', e.target.value)}
                  className="w-full accent-text cursor-pointer"
                />
                <div className="text-2xs text-dim mt-0.5">
                  Percentage of flows from a host required to declare it INFECTED (default: 30%).
                </div>
              </div>

              {/* Slider 4: Minimum Flows per Device */}
              <div>
                <div className="flex justify-between mb-1">
                  <span className="text-dim">MINIMUM FLOWS PER DEVICE:</span>
                  <span className="text-text font-bold">{localParams.min_flows}</span>
                </div>
                <input
                  type="range"
                  min="1"
                  max="100"
                  step="1"
                  value={localParams.min_flows}
                  onChange={(e) => handleSliderChange('min_flows', e.target.value)}
                  className="w-full accent-text cursor-pointer"
                />
                <div className="text-2xs text-dim mt-0.5">
                  Eliminates false classifications on transient single-flow devices (default: 5).
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
