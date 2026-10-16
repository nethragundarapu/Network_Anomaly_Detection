/**
 * SENTINEL AI // REAL-TIME NETWORK TOPOLOGY & PACKET STREAM CANVAS
 * High-performance HTML5 particle flow with live anomaly interception effects.
 */

class NetworkFlowCanvas {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.packets = [];
    this.impacts = [];
    this.nodes = [];
    this.links = [];
    this.isRunning = true;
    this.speed = 1.0;
    this.spawnTimer = 0;
    this.blockedCount = 0;

    this.initDimensions();
    this.initTopology();
    window.addEventListener('resize', () => {
      this.initDimensions();
      this.initTopology();
    });

    this.animate = this.animate.bind(this);
    requestAnimationFrame(this.animate);
  }

  initDimensions() {
    const rect = this.canvas.parentElement.getBoundingClientRect();
    this.width = rect.width;
    this.height = Math.max(rect.height || 280, 280);
    this.canvas.width = this.width * window.devicePixelRatio;
    this.canvas.height = this.height * window.devicePixelRatio;
    this.canvas.style.width = `${this.width}px`;
    this.canvas.style.height = `${this.height}px`;
    this.ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
  }

  initTopology() {
    const cy = this.height / 2;
    const leftX = this.width * 0.15;
    const midX = this.width * 0.50;
    const rightX = this.width * 0.85;

    this.nodes = [
      // Ingress Sources
      { id: 'src1', label: 'Ext-Client 192.168.1.x', x: leftX, y: cy - 65, type: 'source' },
      { id: 'src2', label: 'Remote VPN 10.8.0.x', x: leftX, y: cy + 65, type: 'source' },

      // Sentinel Core
      { id: 'gateway', label: 'SENTINEL AI CORE', x: midX, y: cy, type: 'gateway' },

      // Internal Services
      { id: 'srv1', label: 'SQL Cluster :3306', x: rightX, y: cy - 65, type: 'dest' },
      { id: 'srv2', label: 'Web API :443', x: rightX, y: cy + 65, type: 'dest' }
    ];

    this.links = [
      { from: 'src1', to: 'gateway' },
      { from: 'src2', to: 'gateway' },
      { from: 'gateway', to: 'srv1' },
      { from: 'gateway', to: 'srv2' }
    ];
  }

  spawnPacket(forceAnomaly = false) {
    const isAnomaly = forceAnomaly || Math.random() < 0.22;
    const startNode = Math.random() < 0.5 ? this.nodes[0] : this.nodes[1];
    const gateway = this.nodes[2];

    const protocols = ['HTTPS', 'DNS', 'TCP_SYN', 'SSH', 'TLS'];
    const proto = isAnomaly ? (Math.random() < 0.5 ? 'TCP_SYN' : 'SSH_BRUTE') : protocols[Math.floor(Math.random() * protocols.length)];

    this.packets.push({
      x: startNode.x,
      y: startNode.y,
      startX: startNode.x,
      startY: startNode.y,
      targetX: gateway.x,
      targetY: gateway.y,
      progress: 0,
      speed: (0.012 + Math.random() * 0.008) * this.speed,
      isAnomaly: isAnomaly,
      stage: 'to_gateway',
      protocol: proto,
      size: isAnomaly ? 5 : 3.5
    });
  }

  createImpact(x, y, isAnomaly) {
    this.impacts.push({
      x, y,
      radius: 6,
      maxRadius: isAnomaly ? 38 : 20,
      opacity: 1,
      isAnomaly
    });
    if (isAnomaly) {
      this.blockedCount++;
      const el = document.getElementById('canvas-blocked-counter');
      if (el) el.innerText = this.blockedCount;
    }
  }

  injectThreat() {
    this.spawnPacket(true);
  }

  animate() {
    if (!this.isRunning) {
      requestAnimationFrame(this.animate);
      return;
    }

    this.ctx.clearRect(0, 0, this.width, this.height);

    // 1. Draw Links / Circuit Traces
    this.ctx.lineWidth = 1.5;
    for (const link of this.links) {
      const n1 = this.nodes.find(n => n.id === link.from);
      const n2 = this.nodes.find(n => n.id === link.to);
      if (!n1 || !n2) continue;

      this.ctx.strokeStyle = 'rgba(30, 41, 59, 0.7)';
      this.ctx.beginPath();
      this.ctx.moveTo(n1.x, n1.y);
      this.ctx.lineTo(n2.x, n2.y);
      this.ctx.stroke();

      // Subtle dash glow
      this.ctx.strokeStyle = 'rgba(56, 189, 248, 0.15)';
      this.ctx.setLineDash([4, 12]);
      this.ctx.beginPath();
      this.ctx.moveTo(n1.x, n1.y);
      this.ctx.lineTo(n2.x, n2.y);
      this.ctx.stroke();
      this.ctx.setLineDash([]);
    }

    // 2. Spawn packets
    this.spawnTimer += this.speed;
    if (this.spawnTimer > 35) {
      this.spawnPacket();
      this.spawnTimer = 0;
    }

    // 3. Update & Draw Packets
    const gateway = this.nodes[2];
    const srv1 = this.nodes[3];
    const srv2 = this.nodes[4];

    for (let i = this.packets.length - 1; i >= 0; i--) {
      const p = this.packets[i];
      p.progress += p.speed;

      p.x = p.startX + (p.targetX - p.startX) * p.progress;
      p.y = p.startY + (p.targetY - p.startY) * p.progress;

      // Draw packet
      this.ctx.beginPath();
      this.ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);

      if (p.isAnomaly) {
        this.ctx.fillStyle = '#f43f5e';
        this.ctx.shadowColor = '#f43f5e';
        this.ctx.shadowBlur = 12;
      } else {
        this.ctx.fillStyle = '#10b981';
        this.ctx.shadowColor = '#10b981';
        this.ctx.shadowBlur = 8;
      }
      this.ctx.fill();
      this.ctx.shadowBlur = 0; // reset

      // Reached Gateway
      if (p.stage === 'to_gateway' && p.progress >= 1.0) {
        if (p.isAnomaly) {
          // Blocked at gateway!
          this.createImpact(gateway.x, gateway.y, true);
          this.packets.splice(i, 1);
        } else {
          // Passed inspection -> route to destination server
          this.createImpact(gateway.x, gateway.y, false);
          const dest = Math.random() < 0.5 ? srv1 : srv2;
          p.stage = 'to_dest';
          p.startX = gateway.x;
          p.startY = gateway.y;
          p.targetX = dest.x;
          p.targetY = dest.y;
          p.progress = 0;
        }
      } else if (p.stage === 'to_dest' && p.progress >= 1.0) {
        // Reached internal server safely
        this.packets.splice(i, 1);
      }
    }

    // 4. Update & Draw Impacts
    for (let i = this.impacts.length - 1; i >= 0; i--) {
      const imp = this.impacts[i];
      imp.radius += 1.2;
      imp.opacity -= 0.035;

      this.ctx.beginPath();
      this.ctx.arc(imp.x, imp.y, imp.radius, 0, Math.PI * 2);
      this.ctx.strokeStyle = imp.isAnomaly
        ? `rgba(244, 63, 94, ${Math.max(0, imp.opacity)})`
        : `rgba(16, 185, 129, ${Math.max(0, imp.opacity)})`;
      this.ctx.lineWidth = imp.isAnomaly ? 2.5 : 1.5;
      this.ctx.stroke();

      if (imp.opacity <= 0) {
        this.impacts.splice(i, 1);
      }
    }

    // 5. Draw Network Nodes
    for (const node of this.nodes) {
      if (node.type === 'gateway') {
        // Central Sentinel Gateway
        const size = 32;
        this.ctx.save();
        this.ctx.translate(node.x, node.y);

        // Outer glow circle
        this.ctx.beginPath();
        this.ctx.arc(0, 0, 36, 0, Math.PI * 2);
        this.ctx.fillStyle = 'rgba(6, 182, 212, 0.08)';
        this.ctx.fill();
        this.ctx.strokeStyle = 'rgba(6, 182, 212, 0.4)';
        this.ctx.lineWidth = 1.5;
        this.ctx.stroke();

        // Inner core
        this.ctx.beginPath();
        this.ctx.arc(0, 0, 22, 0, Math.PI * 2);
        this.ctx.fillStyle = '#0f172a';
        this.ctx.fill();
        this.ctx.strokeStyle = '#38bdf8';
        this.ctx.lineWidth = 2;
        this.ctx.shadowColor = '#06b6d4';
        this.ctx.shadowBlur = 14;
        this.ctx.stroke();
        this.ctx.shadowBlur = 0;

        // Label
        this.ctx.fillStyle = '#38bdf8';
        this.ctx.font = 'bold 10px JetBrains Mono, monospace';
        this.ctx.textAlign = 'center';
        this.ctx.fillText('SENTINEL', 0, 3);
        this.ctx.font = '9px Inter, sans-serif';
        this.ctx.fillStyle = '#94a3b8';
        this.ctx.fillText('AI DEFENSE CORE', 0, 48);

        this.ctx.restore();
      } else {
        // Peripheral Nodes
        this.ctx.save();
        this.ctx.translate(node.x, node.y);

        this.ctx.beginPath();
        this.ctx.arc(0, 0, 14, 0, Math.PI * 2);
        this.ctx.fillStyle = '#1e293b';
        this.ctx.fill();
        this.ctx.strokeStyle = node.type === 'source' ? '#64748b' : '#34d399';
        this.ctx.lineWidth = 1.5;
        this.ctx.stroke();

        this.ctx.fillStyle = '#cbd5e1';
        this.ctx.font = '10px Inter, sans-serif';
        this.ctx.textAlign = 'center';
        this.ctx.fillText(node.label, 0, 26);

        this.ctx.restore();
      }
    }

    requestAnimationFrame(this.animate);
  }
}

window.NetworkFlowCanvas = NetworkFlowCanvas;
