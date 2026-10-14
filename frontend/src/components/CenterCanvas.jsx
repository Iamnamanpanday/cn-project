import React, { useRef, useEffect, useState, useMemo, useCallback } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { useConsoleStore } from '../store/useConsoleStore'

export default function CenterCanvas() {
  const containerRef = useRef(null)
  const fgRef = useRef(null)
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 })
  const [hoveredNode, setHoveredNode] = useState(null)

  const {
    data,
    selectedHostIp,
    selectHost,
    quarantinedHosts,
    isPlaying,
  } = useConsoleStore()

  // Track container dimensions with ResizeObserver
  useEffect(() => {
    if (!containerRef.current) return
    const updateSize = () => {
      if (containerRef.current) {
        const { clientWidth, clientHeight } = containerRef.current
        setDimensions({
          width: clientWidth || 800,
          height: clientHeight || 600,
        })
      }
    }
    updateSize()
    const observer = new ResizeObserver(updateSize)
    observer.observe(containerRef.current)
    return () => observer.disconnect()
  }, [])

  // Prepare graph data
  const graphData = useMemo(() => {
    const rawNodes = data?.graph?.nodes || []
    const rawLinks = data?.graph?.links || []

    // Filter links if one endpoint is quarantined (simulate isolation)
    const activeLinks = rawLinks.filter(
      (link) => {
        const srcId = typeof link.source === 'object' ? link.source.id : link.source
        const tgtId = typeof link.target === 'object' ? link.target.id : link.target
        return !quarantinedHosts.includes(srcId) && !quarantinedHosts.includes(tgtId)
      }
    )

    // Deep copy nodes for force-graph simulation mutations
    const nodes = rawNodes.map((n) => ({
      ...n,
      isQuarantined: quarantinedHosts.includes(n.id),
      isSelected: selectedHostIp === n.id,
    }))

    const links = activeLinks.map((l) => ({
      ...l,
      weight: l.weight || 1,
    }))

    return { nodes, links }
  }, [data, quarantinedHosts, selectedHostIp])

  // Custom node rendering on HTML5 canvas
  const drawNode = useCallback((node, ctx, globalScale) => {
    const isSelected = node.isSelected
    const isQuarantined = node.isQuarantined
    const isInfected = node.kind === 'infected device' || node.is_infected
    const isSuspiciousDest = node.kind === 'suspicious destination'

    // Node Radius
    const r = isInfected ? 9 : isSuspiciousDest ? 6 : 4

    // 1. Quarantined representation: severed isolation ring
    if (isQuarantined) {
      ctx.beginPath()
      ctx.arc(node.x, node.y, r + 6, 0, 2 * Math.PI, false)
      ctx.strokeStyle = '#ff3b30'
      ctx.lineWidth = 1.5
      ctx.setLineDash([3, 3])
      ctx.stroke()
      ctx.setLineDash([])

      ctx.beginPath()
      ctx.arc(node.x, node.y, r, 0, 2 * Math.PI, false)
      ctx.fillStyle = '#4a1512'
      ctx.fill()
      ctx.strokeStyle = '#ff3b30'
      ctx.stroke()
    }
    // 2. Infected node: red + pulsing ring
    else if (isInfected) {
      // Pulsing outer ring
      const time = Date.now() / 1000
      const pulseR = r + 4 + Math.sin(time * 3) * 3
      ctx.beginPath()
      ctx.arc(node.x, node.y, pulseR, 0, 2 * Math.PI, false)
      ctx.strokeStyle = 'rgba(255, 59, 48, 0.5)'
      ctx.lineWidth = 1.2
      ctx.stroke()

      // Core node
      ctx.beginPath()
      ctx.arc(node.x, node.y, r, 0, 2 * Math.PI, false)
      ctx.fillStyle = '#ff3b30'
      ctx.fill()
      ctx.strokeStyle = '#c7d1cf'
      ctx.lineWidth = 1.5
      ctx.stroke()
    }
    // 3. Suspicious destination: amber
    else if (isSuspiciousDest) {
      ctx.beginPath()
      ctx.arc(node.x, node.y, r, 0, 2 * Math.PI, false)
      ctx.fillStyle = '#d9a441'
      ctx.fill()
      ctx.strokeStyle = '#1b2326'
      ctx.lineWidth = 1
      ctx.stroke()
    }
    // 4. Normal host / peer: dim
    else {
      ctx.beginPath()
      ctx.arc(node.x, node.y, r, 0, 2 * Math.PI, false)
      ctx.fillStyle = '#5b6968'
      ctx.fill()
      ctx.strokeStyle = '#1b2326'
      ctx.lineWidth = 1
      ctx.stroke()
    }

    // Selected indicator ring
    if (isSelected) {
      ctx.beginPath()
      ctx.arc(node.x, node.y, r + 4, 0, 2 * Math.PI, false)
      ctx.strokeStyle = '#c7d1cf'
      ctx.lineWidth = 1.5
      ctx.stroke()
    }

    // Text label for infected hosts and top destinations
    if (isInfected || isSuspiciousDest || globalScale > 1.8) {
      const label = node.id
      const fontSize = Math.max(9 / globalScale, 3)
      ctx.font = `${fontSize}px "IBM Plex Mono", monospace`
      ctx.fillStyle = isInfected ? '#ff3b30' : isSuspiciousDest ? '#d9a441' : '#c7d1cf'
      ctx.textAlign = 'center'
      ctx.textBaseline = 'bottom'
      ctx.fillText(label, node.x, node.y - r - 2)
    }
  }, [])

  const handleZoomReset = () => {
    fgRef.current?.zoomToFit(400, 40)
  }

  return (
    <main
      ref={containerRef}
      className="flex-1 h-full bg-bg relative overflow-hidden bg-grid select-none flex flex-col"
    >
      {/* Topology Canvas Overlay Controls */}
      <div className="absolute top-2 left-2 z-10 flex items-center gap-2">
        <div className="bg-panel border border-line px-2 py-1 text-2xs font-mono text-dim flex items-center gap-2">
          <span>TOPOLOGY: {graphData.nodes.length} NODES / {graphData.links.length} EDGES</span>
        </div>
        <button
          onClick={handleZoomReset}
          className="bg-panel border border-line px-2 py-1 text-2xs font-mono text-dim hover:text-text hover:border-dim uppercase"
          title="Reset Zoom & Center View"
        >
          RESET ZOOM
        </button>
      </div>

      {/* Legend */}
      <div className="absolute top-2 right-2 z-10 bg-panel/90 border border-line p-2 text-2xs font-mono text-dim flex flex-col gap-1 pointer-events-none">
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 bg-threat border border-threat inline-block"></span>
          <span className="text-threat font-bold">INFECTED HOST</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 bg-warn inline-block"></span>
          <span className="text-warn">SUSPICIOUS DEST</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 bg-dim inline-block"></span>
          <span>NORMAL PEER</span>
        </div>
        {quarantinedHosts.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 border border-threat bg-threat-dim inline-block"></span>
            <span className="text-threat">QUARANTINED</span>
          </div>
        )}
      </div>

      {/* Hover Tooltip Readout */}
      {hoveredNode && (
        <div className="absolute bottom-2 left-2 z-10 bg-panel border border-line p-2 text-xs font-mono text-text shadow-lg pointer-events-none">
          <div className="font-bold text-text uppercase">NODE: {hoveredNode.id}</div>
          <div className="text-dim text-2xs">KIND: {hoveredNode.kind || 'PEER'}</div>
          {hoveredNode.status && (
            <div className={`text-2xs font-bold ${hoveredNode.status === 'INFECTED' ? 'text-threat' : 'text-ok'}`}>
              STATUS: {hoveredNode.status}
            </div>
          )}
        </div>
      )}

      {/* Force Graph 2D Canvas */}
      {dimensions.width > 0 && dimensions.height > 0 && (
        <ForceGraph2D
          ref={fgRef}
          width={dimensions.width}
          height={dimensions.height}
          graphData={graphData}
          nodeCanvasObject={drawNode}
          nodeRelSize={6}
          linkColor={(link) => (link.is_threat ? 'rgba(255, 59, 48, 0.4)' : 'rgba(91, 105, 104, 0.25)')}
          linkWidth={(link) => (link.is_threat ? 1.5 : 1)}
          linkDirectionalParticles={(link) => Math.min(6, Math.max(1, Math.round(Math.log10(link.weight + 1) * 2)))}
          linkDirectionalParticleSpeed={(link) => (link.is_threat ? 0.007 : 0.003)}
          linkDirectionalParticleWidth={2}
          linkDirectionalParticleColor={(link) => (link.is_threat ? '#ff3b30' : '#3fb27f')}
          onNodeClick={(node) => selectHost(node.id)}
          onNodeHover={(node) => setHoveredNode(node)}
          cooldownTicks={80}
          d3AlphaDecay={0.03}
          d3VelocityDecay={0.3}
          backgroundColor="#07090a"
        />
      )}
    </main>
  )
}
