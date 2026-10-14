import React from 'react'
import { useConsoleStore } from '../store/useConsoleStore'

export default function ReportOverlay() {
  const { data, setOverlay } = useConsoleStore()

  const summary = data?.summary || {}
  const devices = data?.devices || []
  const infectedDevices = devices.filter((d) => d.status === 'INFECTED')
  const destinations = data?.destinations || []
  const rules = data?.rules || {}
  const nowUtc = new Date().toISOString()

  const handlePrint = () => {
    window.print()
  }

  return (
    <div className="fixed inset-0 bg-black/90 z-50 overflow-y-auto p-4 sm:p-8 flex justify-center animate-in fade-in duration-100">
      {/* Container: on screen it uses dark theme; in print it switches to clean white via report-printable class */}
      <div className="report-printable w-full max-w-4xl bg-panel border border-line p-8 flex flex-col space-y-6 shadow-2xl relative my-auto">
        {/* Screen Action Bar (hidden when printing) */}
        <div className="no-print flex items-center justify-between pb-4 border-b border-line">
          <div className="flex items-center gap-2">
            <span className="font-condensed font-bold tracking-wider text-base uppercase text-text">
              INCIDENT REPORT GENERATOR
            </span>
            <span className="text-2xs font-mono text-dim">[PRINT / PDF EXPORT READY]</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handlePrint}
              className="px-3 py-1 bg-text text-black font-condensed font-bold text-xs uppercase tracking-wider hover:bg-dim hover:text-white"
            >
              SAVE AS PDF / PRINT
            </button>
            <button
              onClick={() => setOverlay(null)}
              className="px-3 py-1 border border-line text-xs font-mono text-dim hover:text-text hover:border-dim uppercase"
            >
              ESC [CLOSE]
            </button>
          </div>
        </div>

        {/* Report Document Header */}
        <div className="border-b border-line pb-4">
          <div className="flex items-center justify-between mb-2">
            <h1 className="text-2xl font-condensed font-bold tracking-widest uppercase">
              SECURITY INCIDENT &amp; BOTNET TELEMETRY REPORT
            </h1>
            <div className="text-xs font-mono text-right">
              <div>INCIDENT REF: SIGINT-IOT-{nowUtc.substring(0, 10)}</div>
              <div className="text-dim">GENERATED: {nowUtc}</div>
            </div>
          </div>
          <div className="text-xs font-mono text-dim">
            ORGANIZATION: IoT Security Operations Center // Dual Supervised RF + Autoencoder Detection Fabric
          </div>
        </div>

        {/* Executive Summary Section */}
        <div>
          <h2 className="text-xs font-condensed font-bold uppercase tracking-wider mb-2 border-b border-line/60 pb-1">
            1. EXECUTIVE TELEMETRY SUMMARY
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
            <div className="border border-line p-2">
              <div className="text-2xs text-dim uppercase">TOTAL FLOWS ANALYSED</div>
              <div className="text-lg font-bold">{summary.total?.toLocaleString() ?? 0}</div>
            </div>
            <div className="border border-line p-2">
              <div className="text-2xs text-dim uppercase">FLAGGED BOTNET FLOWS</div>
              <div className="text-lg font-bold text-threat">
                {summary.flagged?.toLocaleString() ?? 0} ({summary.flagged_pct ?? 0}%)
              </div>
            </div>
            <div className="border border-line p-2">
              <div className="text-2xs text-dim uppercase">COMPROMISED HOSTS</div>
              <div className="text-lg font-bold text-threat">
                {summary.infected_devices ?? 0} OF {devices.length}
              </div>
            </div>
            <div className="border border-line p-2">
              <div className="text-2xs text-dim uppercase">EVALUATED THREAT LEVEL</div>
              <div className="text-lg font-bold text-threat uppercase">
                {summary.threat_level || 'NOMINAL'}
              </div>
            </div>
          </div>
        </div>

        {/* Compromised Hosts */}
        <div>
          <h2 className="text-xs font-condensed font-bold uppercase tracking-wider mb-2 border-b border-line/60 pb-1">
            2. COMPROMISED INTERNAL HOSTS (ISOLATION RECOMMENDED)
          </h2>
          {infectedDevices.length === 0 ? (
            <div className="text-xs font-mono text-ok p-2 border border-line">
              NO INTERNAL HOSTS EXCEEDED INFECTION THRESHOLD. FABRIC STATUS NOMINAL.
            </div>
          ) : (
            <div className="border border-line overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs font-mono">
                <thead>
                  <tr className="bg-panel border-b border-line text-2xs text-dim uppercase">
                    <th className="p-2">SOURCE IP</th>
                    <th className="p-2">TOTAL FLOWS</th>
                    <th className="p-2">FLAGGED FLOWS</th>
                    <th className="p-2">RISK %</th>
                    <th className="p-2">UNIQUE TARGETS</th>
                    <th className="p-2">STATUS</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line/40">
                  {infectedDevices.map((d) => (
                    <tr key={d.src_ip}>
                      <td className="p-2 font-bold text-threat">{d.src_ip}</td>
                      <td className="p-2">{d.flows}</td>
                      <td className="p-2 font-bold text-threat">{d.flagged}</td>
                      <td className="p-2">{d.flagged_pct}%</td>
                      <td className="p-2">{d.unique_dsts}</td>
                      <td className="p-2 font-bold text-threat uppercase">{d.status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Top Suspicious Destinations (C2 Candidates) */}
        <div>
          <h2 className="text-xs font-condensed font-bold uppercase tracking-wider mb-2 border-b border-line/60 pb-1">
            3. TOP SUSPICIOUS DESTINATIONS &amp; C2 CANDIDATES
          </h2>
          <div className="border border-line overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs font-mono">
              <thead>
                <tr className="bg-panel border-b border-line text-2xs text-dim uppercase">
                  <th className="p-2">DESTINATION IP</th>
                  <th className="p-2">FLAGGED FLOWS</th>
                  <th className="p-2">SOURCE DEVICES</th>
                  <th className="p-2">TARGET PORTS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line/40">
                {destinations.slice(0, 8).map((dst) => (
                  <tr key={dst.dst_ip}>
                    <td className="p-2 font-bold">{dst.dst_ip}</td>
                    <td className="p-2">{dst.flagged_flows}</td>
                    <td className="p-2">{dst.from_devices}</td>
                    <td className="p-2 text-dim">{dst.ports}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recommended Firewall Containment Blocks */}
        <div>
          <h2 className="text-xs font-condensed font-bold uppercase tracking-wider mb-2 border-b border-line/60 pb-1">
            4. RECOMMENDED AUTOMATED FIREWALL BLOCK RULES
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
            <div>
              <div className="text-2xs text-dim uppercase mb-1">LINUX IPTABLES:</div>
              <pre className="p-2 border border-line bg-panel text-2xs overflow-x-auto whitespace-pre">
                {rules.iptables || '# No rules generated'}
              </pre>
            </div>
            <div>
              <div className="text-2xs text-dim uppercase mb-1">WINDOWS FIREWALL (NETSH):</div>
              <pre className="p-2 border border-line bg-panel text-2xs overflow-x-auto whitespace-pre">
                {rules.netsh || 'REM No rules generated'}
              </pre>
            </div>
          </div>
        </div>

        {/* Methodology & Limitations Notes */}
        <div className="border-t border-line pt-3 text-2xs font-mono text-dim leading-relaxed">
          <div className="font-bold uppercase text-text mb-1">METHODOLOGY &amp; SENSITIVITY DISCLOSURE:</div>
          <div>
            Detection executed via Dual-Engine Architecture: Random Forest (trained on known attack vectors) paired with an MLP Autoencoder (reconstruction error thresholded on benign distributions). Analysis limited to summary flow statistics and 1-minute window metrics; packet payloads remain uninspected. Review generated mitigation rules before applying to perimeter firewalls.
          </div>
        </div>
      </div>
    </div>
  )
}
