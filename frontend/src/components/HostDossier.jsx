import React from 'react'
import { useConsoleStore } from '../store/useConsoleStore'

export default function HostDossier() {
  const {
    data,
    selectedHostIp,
    closeHostDossier,
    hostExplanation,
    explaining,
    quarantinedHosts,
    toggleQuarantine,
  } = useConsoleStore()

  if (!selectedHostIp) return null

  const devInfo = data?.devices?.find((d) => d.src_ip === selectedHostIp) || {
    src_ip: selectedHostIp,
    flows: 0,
    flagged: 0,
    flagged_pct: 0,
    status: 'clean',
    unique_dsts: 0,
    kill_chain: { recon: false, attack: false, c2: false },
  }

  const isInfected = devInfo.status === 'INFECTED'
  const isQuarantined = quarantinedHosts.includes(selectedHostIp)
  const riskScore = devInfo.flagged_pct ?? 0
  const killChain = devInfo.kill_chain || { recon: false, attack: false, c2: false }

  // Host-specific firewall rules
  const hostRules = data?.per_device_rules?.[selectedHostIp] || {
    iptables: `# Linux iptables quarantine for ${selectedHostIp}\niptables -A FORWARD -s ${selectedHostIp} -j DROP\niptables -A FORWARD -d ${selectedHostIp} -j DROP`,
    netsh: `REM Windows Firewall quarantine for ${selectedHostIp}\nnetsh advfirewall firewall add rule name="Quarantine ${selectedHostIp}" dir=out action=block remoteip=${selectedHostIp}`,
  }

  return (
    <div className="fixed inset-y-0 right-0 w-[440px] bg-panel border-l border-line z-40 flex flex-col shadow-2xl select-none animate-in slide-in-from-right duration-150">
      {/* Dossier Header */}
      <div className="p-3 border-b border-line bg-bg flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="font-condensed font-bold tracking-wider text-base uppercase text-text">
            HOST DOSSIER
          </span>
          <span className="font-mono text-xs text-dim">[{selectedHostIp}]</span>
        </div>
        <button
          onClick={closeHostDossier}
          className="px-2 py-0.5 text-xs font-mono border border-line text-dim hover:text-text hover:border-dim uppercase"
          title="Close Dossier (Esc)"
        >
          ESC [X]
        </button>
      </div>

      {/* Dossier Body */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Risk Score & Status Readout */}
        <div className="border border-line bg-bg p-3">
          <div className="text-2xs font-mono text-dim uppercase mb-1">
            MEASURED RISK SCORE // INFECTION PROBABILITY
          </div>
          <div className="flex items-baseline justify-between mb-2">
            <div className="flex items-baseline gap-2">
              <span className={`text-4xl font-condensed font-bold tracking-tight ${isInfected ? 'text-threat' : 'text-text'}`}>
                {riskScore.toFixed(1)}%
              </span>
              <span className="text-2xs font-mono text-dim">
                ({devInfo.flagged}/{devInfo.flows} FLOWS FLAGGED)
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              {isQuarantined && (
                <span className="text-2xs px-1.5 py-0.5 border border-threat bg-threat-dim text-threat font-condensed font-bold uppercase tracking-wider">
                  QUARANTINED
                </span>
              )}
              <span
                className={`text-xs px-2 py-0.5 font-condensed font-bold tracking-wider uppercase border ${
                  isInfected
                    ? 'border-threat text-threat bg-threat-dim pulse-threat'
                    : 'border-ok text-ok bg-panel'
                }`}
              >
                {devInfo.status}
              </span>
            </div>
          </div>

          {/* Thin Risk Bar */}
          <div className="w-full bg-panel h-1.5 border border-line/60 overflow-hidden">
            <div
              className={`h-full ${isInfected ? 'bg-threat' : riskScore > 10 ? 'bg-warn' : 'bg-dim'}`}
              style={{ width: `${Math.min(100, Math.max(2, riskScore))}%` }}
            />
          </div>

          <div className="mt-2 pt-2 border-t border-line/40 grid grid-cols-2 gap-2 text-2xs font-mono text-dim">
            <div>
              TOTAL FLOWS: <span className="text-text font-bold">{devInfo.flows}</span>
            </div>
            <div>
              UNIQUE TARGET DSTS: <span className="text-text font-bold">{devInfo.unique_dsts}</span>
            </div>
          </div>
        </div>

        {/* Kill Chain Progression Strip */}
        <div className="border border-line bg-bg p-3">
          <div className="text-2xs font-mono text-dim uppercase mb-2 flex items-center justify-between">
            <span>KILL-CHAIN PROGRESSION</span>
            <span className="text-dim/70">STAGE SURVEILLANCE</span>
          </div>

          <div className="grid grid-cols-3 gap-1 text-center font-condensed tracking-wider">
            {/* Stage 1: RECON */}
            <div
              className={`p-2 border ${
                killChain.recon
                  ? 'border-warn bg-warn/10 text-warn'
                  : 'border-line bg-panel text-dim/60'
              }`}
            >
              <div className="text-xs font-bold uppercase">RECON</div>
              <div className="text-2xs font-mono">PORT SCAN</div>
            </div>

            {/* Stage 2: ATTACK */}
            <div
              className={`p-2 border ${
                killChain.attack
                  ? 'border-threat bg-threat-dim text-threat font-bold'
                  : 'border-line bg-panel text-dim/60'
              }`}
            >
              <div className="text-xs uppercase">ATTACK</div>
              <div className="text-2xs font-mono">SSH BRUTE</div>
            </div>

            {/* Stage 3: C2 */}
            <div
              className={`p-2 border ${
                killChain.c2
                  ? 'border-threat bg-threat-dim text-threat font-bold'
                  : 'border-line bg-panel text-dim/60'
              }`}
            >
              <div className="text-xs uppercase">C2</div>
              <div className="text-2xs font-mono">BEACONING</div>
            </div>
          </div>
          <div className="mt-1.5 text-2xs font-mono text-dim">
            {killChain.recon || killChain.attack || killChain.c2
              ? '* Active stages illuminated based on observed ports & statistical flow signatures.'
              : '* Quiescent: No recognized attack phases triggered.'}
          </div>
        </div>

        {/* Why Flagged: Behavioural Deviations */}
        <div className="border border-line bg-bg p-3">
          <div className="text-2xs font-mono text-dim uppercase mb-2 flex items-center justify-between">
            <span>WHY FLAGGED // BEHAVIOURAL DEVIATION</span>
            <span className="text-dim/70">ROBUST Z-SCORE</span>
          </div>

          {explaining ? (
            <div className="p-3 text-center text-dim font-mono text-xs">
              COMPUTING ROBUST Z-SCORES VS BENIGN BASELINE...
            </div>
          ) : hostExplanation?.deviations?.length > 0 ? (
            <div className="space-y-2">
              {hostExplanation.deviations.map((dev, idx) => (
                <div key={idx} className="p-1.5 bg-panel border border-line text-xs font-mono">
                  <div className="flex items-center justify-between text-2xs mb-0.5">
                    <span className="text-text font-bold uppercase">{dev.label}</span>
                    <span className="text-dim">
                      Z: <span className="text-text font-bold">{dev.z_score > 0 ? `+${dev.z_score}` : dev.z_score}</span>
                    </span>
                  </div>
                  <div className="text-2xs text-dim leading-snug">
                    {dev.description}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-2 text-2xs font-mono text-dim">
              No significant deviations detected beyond normal benign baseline tolerances.
            </div>
          )}
        </div>

        {/* Mitigation Quarantine Controls (Simulation Only) */}
        <div className="border border-line bg-bg p-3">
          <div className="text-2xs font-mono text-dim uppercase mb-1">
            MITIGATION ACTION // QUARANTINE SIMULATION
          </div>
          <div className="text-2xs text-dim font-mono mb-2">
            NOTICE: Simulation only. Isolates this node in the topology canvas, appends containment drop rules, and logs SIM_QUARANTINE in event stream. Nothing is executed on any production network interface.
          </div>

          <button
            onClick={() => toggleQuarantine(selectedHostIp)}
            className={`w-full py-2 px-3 text-xs font-condensed font-bold tracking-wider uppercase border ${
              isQuarantined
                ? 'bg-panel border-ok text-ok hover:bg-ok/10'
                : 'bg-threat-dim border-threat text-threat hover:bg-threat/20 pulse-threat'
            }`}
          >
            {isQuarantined ? 'RELEASE HOST QUARANTINE (SIMULATION)' : 'EXECUTE SIMULATED QUARANTINE'}
          </button>

          {/* Generated Firewall Rules */}
          <div className="mt-3 space-y-2 text-2xs font-mono">
            <div>
              <div className="text-dim uppercase mb-0.5">GENERATED LINUX IPTABLES:</div>
              <pre className="p-1.5 bg-panel border border-line text-text overflow-x-auto whitespace-pre">
                {hostRules.iptables}
              </pre>
            </div>
            <div>
              <div className="text-dim uppercase mb-0.5">GENERATED WINDOWS NETSH:</div>
              <pre className="p-1.5 bg-panel border border-line text-text overflow-x-auto whitespace-pre">
                {hostRules.netsh}
              </pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
