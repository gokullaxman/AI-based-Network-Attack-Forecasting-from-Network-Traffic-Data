/**
 * Cybersecurity Attack Visualization & Network Threat Monitoring Dashboard
 * Security Operations Center (SOC) Console Engine
 * STRICT REAL-DATA-ONLY ARCHITECTURE (Phase 5: Dashboard UI & 3D Visualization)
 * 
 * Integrity Guarantees:
 * - Real packet capture telemetry and Npcap health diagnostics
 * - Operating mode quarantine (LIVE, OFFLINE PCAP, CONNECTION METADATA, SIMULATION)
 * - Three.js 3D WebGL topology rendered exclusively from verified endpoint observations
 * - Zero fabricated fallback devices, random time-series, or synthetic alerts
 * - Model forecasting strictly gated behind validated 10-flow sequence verification
 */

(function () {
  'use strict';

  // State Management
  const state = {
    activeView: 'soc3ColumnView',
    filterCategory: 'ALL',
    filterSeverity: 'ALL',
    filterStatus: 'ALL',
    searchTerm: '',
    selectedNodeId: null,
    selectedLogId: null,
    currentMode: 'live',
    selectedInterfaceId: null,
    isCapturing: false,
    autoRotate3D: false,
    captureHealth: null,
    topologyData: { nodes: [], edges: [] },
    timeSeriesData: [],
    recentPackets: [],
    threatLogs: [],
    latestPrediction: null,
    activeAlertIp: null,
    lastSuccessfulPoll: null
  };

  // =========================================================================
  // DOM REFERENCES
  // =========================================================================
  const dom = {
    // Navigation
    tabSocDashboard: document.getElementById('tabSocDashboard'),
    tabModelDeepDive: document.getElementById('tabModelDeepDive'),
    tabTemporalExperimental: document.getElementById('tabTemporalExperimental'),
    soc3ColumnView: document.getElementById('soc3ColumnView'),
    modelDeepDiveView: document.getElementById('modelDeepDiveView'),
    temporalExperimentalView: document.getElementById('temporalExperimentalView'),

    // Phase 9C: Temporal Experimental Forecaster DOM
    temporalSampleSelect: document.getElementById('temporalSampleSelect'),
    temporalSampleNotesBox: document.getElementById('temporalSampleNotesBox'),
    btnRunTemporalForecast: document.getElementById('btnRunTemporalForecast'),
    btnTestPacketRejection: document.getElementById('btnTestPacketRejection'),
    temporalOutputBadge: document.getElementById('temporalOutputBadge'),
    temporalScoreCircle: document.getElementById('temporalScoreCircle'),
    temporalScoreVal: document.getElementById('temporalScoreVal'),
    temporalDecisionTitle: document.getElementById('temporalDecisionTitle'),
    temporalDecisionDesc: document.getElementById('temporalDecisionDesc'),
    temporalOutputDetails: document.getElementById('temporalOutputDetails'),

    // Header elements
    sourceStatusBadge: document.getElementById('sourceStatusBadge'),
    sourceTypePill: document.getElementById('sourceTypePill'),
    sourceTextLabel: document.getElementById('sourceTextLabel'),
    headerPulseDot: document.getElementById('headerPulseDot'),
    headerPingInput: document.getElementById('headerPingInput'),
    headerPingBtn: document.getElementById('headerPingBtn'),
    btnAdvanceStream: document.getElementById('btnAdvanceStream'),
    btnExportExcel: document.getElementById('btnExportExcel'),

    // Phase 5: Capture Health Banner Elements
    captureHealthBanner: document.getElementById('captureHealthBanner'),
    healthIndicatorBadge: document.getElementById('healthIndicatorBadge'),
    healthStatusDot: document.getElementById('healthStatusDot'),
    healthStatusText: document.getElementById('healthStatusText'),
    healthBackendText: document.getElementById('healthBackendText'),
    healthInterfaceText: document.getElementById('healthInterfaceText'),
    healthPacketCount: document.getElementById('healthPacketCount'),
    healthLastSeen: document.getElementById('healthLastSeen'),
    systemModeSelect: document.getElementById('systemModeSelect'),
    systemInterfaceSelect: document.getElementById('systemInterfaceSelect'),
    healthDiagnosticStrip: document.getElementById('healthDiagnosticStrip'),
    healthDiagnosticTitle: document.getElementById('healthDiagnosticTitle'),
    healthDiagnosticMsg: document.getElementById('healthDiagnosticMsg'),

    // Left Column: Traffic Counters & Stats
    normalTrafficCount: document.getElementById('normalTrafficCount'),
    normalTrafficPct: document.getElementById('normalTrafficPct'),
    normalBarFill: document.getElementById('normalBarFill'),
    suspiciousTrafficCount: document.getElementById('suspiciousTrafficCount'),
    suspiciousTrafficPct: document.getElementById('suspiciousTrafficPct'),
    suspiciousBarFill: document.getElementById('suspiciousBarFill'),
    maliciousTrafficCount: document.getElementById('maliciousTrafficCount'),
    maliciousTrafficPct: document.getElementById('maliciousTrafficPct'),
    maliciousBarFill: document.getElementById('maliciousBarFill'),
    totalTrafficCount: document.getElementById('totalTrafficCount'),
    segNormal: document.getElementById('segNormal'),
    segSuspicious: document.getElementById('segSuspicious'),
    segMalicious: document.getElementById('segMalicious'),

    leftPacketRate: document.getElementById('leftPacketRate'),
    leftBandwidth: document.getElementById('leftBandwidth'),
    leftActiveFlows: document.getElementById('leftActiveFlows'),
    leftDataVolume: document.getElementById('leftDataVolume'),

    // Time-Series Canvas
    trafficTimeSeriesCanvas: document.getElementById('trafficTimeSeriesCanvas'),
    chartTooltip: document.getElementById('chartTooltip'),

    // Severities
    sevCriticalCount: document.getElementById('sevCriticalCount'),
    sevHighCount: document.getElementById('sevHighCount'),
    sevMediumCount: document.getElementById('sevMediumCount'),
    sevLowCount: document.getElementById('sevLowCount'),
    sevInfoCount: document.getElementById('sevInfoCount'),

    // Left AI Forecast
    leftForecastOutput: document.getElementById('leftForecastOutput'),
    leftCurrStage: document.getElementById('leftCurrStage'),
    leftNextStage: document.getElementById('leftNextStage'),
    leftRiskScore: document.getElementById('leftRiskScore'),
    leftRiskBadge: document.getElementById('leftRiskBadge'),
    leftConfidencePct: document.getElementById('leftConfidencePct'),

    // Controls
    socCaptureSourceSelect: document.getElementById('socCaptureSourceSelect'),
    socToggleCaptureBtn: document.getElementById('socToggleCaptureBtn'),
    socCaptureBtnLabel: document.getElementById('socCaptureBtnLabel'),
    socClearBufferBtn: document.getElementById('socClearBufferBtn'),
    socPingTargetInput: document.getElementById('socPingTargetInput'),
    socSendPingBtn: document.getElementById('socSendPingBtn'),
    socLoadSamplePcapBtn: document.getElementById('socLoadSamplePcapBtn'),
    socPcapFileInput: document.getElementById('socPcapFileInput'),

    // Center Column: 3D Canvas & Overlays
    threeJsCanvas: document.getElementById('threeJsCanvas'),
    threejsViewportContainer: document.getElementById('threejsViewportContainer'),
    threeJsTooltip: document.getElementById('threeJsTooltip'),
    threeNodeInspector: document.getElementById('threeNodeInspector'),
    btnCloseNodeInspector: document.getElementById('btnCloseNodeInspector'),
    threeJsEmptyState: document.getElementById('threeJsEmptyState'),
    emptyCaptureStatusTag: document.getElementById('emptyCaptureStatusTag'),

    insRolePill: document.getElementById('insRolePill'),
    insCatPill: document.getElementById('insCatPill'),
    insNodeLabel: document.getElementById('insNodeLabel'),
    insNodeIp: document.getElementById('insNodeIp'),
    insCopyIpBtn: document.getElementById('insCopyIpBtn'),
    insNodeDesc: document.getElementById('insNodeDesc'),
    insNodeMac: document.getElementById('insNodeMac'),
    insNodeOs: document.getElementById('insNodeOs'),
    insNodeSessions: document.getElementById('insNodeSessions'),
    insNodeRisk: document.getElementById('insNodeRisk'),
    insFilterLogsBtn: document.getElementById('insFilterLogsBtn'),

    btnResetCamera: document.getElementById('btnResetCamera'),
    btnAutoRotate: document.getElementById('btnAutoRotate'),
    btnFocusAlertNode: document.getElementById('btnFocusAlertNode'),
    btnToggleFullscreen: document.getElementById('btnToggleFullscreen'),
    hudNodesOnline: document.getElementById('hudNodesOnline'),
    hudEdgesActive: document.getElementById('hudEdgesActive'),
    hudThreatNodes: document.getElementById('hudThreatNodes'),

    // Right Column: Threat Detection Panel
    mainSecurityAlertBanner: document.getElementById('mainSecurityAlertBanner'),
    alertBannerSev: document.getElementById('alertBannerSev'),
    alertBannerStatus: document.getElementById('alertBannerStatus'),
    alertBannerTime: document.getElementById('alertBannerTime'),
    alertBannerTitle: document.getElementById('alertBannerTitle'),
    alertBannerMsg: document.getElementById('alertBannerMsg'),
    alertBannerIp: document.getElementById('alertBannerIp'),
    alertBtnInvestigate: document.getElementById('alertBtnInvestigate'),
    alertBtnLocate3D: document.getElementById('alertBtnLocate3D'),
    alertBtnAcknowledge: document.getElementById('alertBtnAcknowledge'),

    logSearchInput: document.getElementById('logSearchInput'),
    filterSeveritySelect: document.getElementById('filterSeveritySelect'),
    filterStatusSelect: document.getElementById('filterStatusSelect'),
    btnRefreshLogs: document.getElementById('btnRefreshLogs'),
    threatLogsCountBadge: document.getElementById('threatLogsCountBadge'),
    threatLogsFeed: document.getElementById('threatLogsFeed'),

    // Event Details Drawer
    eventDetailsDrawer: document.getElementById('eventDetailsDrawer'),
    detailLogIdTitle: document.getElementById('detailLogIdTitle'),
    btnCloseDetailsDrawer: document.getElementById('btnCloseDetailsDrawer'),
    drawerBodyContent: document.getElementById('drawerBodyContent'),
    socDefenseList: document.getElementById('socDefenseList'),

    // Deep-Dive View DOMs
    deepCurrStage: document.getElementById('deepCurrStage'),
    deepNextStage: document.getElementById('deepNextStage'),
    deepConfVal: document.getElementById('deepConfVal'),
    deepSensorsGrid: document.getElementById('deepSensorsGrid'),
    deepShapTable: document.getElementById('deepShapTable'),
    deepShapRankingBody: document.getElementById('deepShapRankingBody'),
    deepForceBarsList: document.getElementById('deepForceBarsList'),
    btnShapRanking: document.getElementById('btnShapRanking'),
    btnShapForce: document.getElementById('btnShapForce'),
    shapRankingView: document.getElementById('shapRankingView'),
    shapForceView: document.getElementById('shapForceView'),
    deepLivePacketTableBody: document.getElementById('deepLivePacketTableBody'),
    deepPacketTableCount: document.getElementById('deepPacketTableCount'),
    deepPacketInspectorPanel: document.getElementById('deepPacketInspectorPanel'),
    deepInspectorDetails: document.getElementById('deepInspectorDetails'),
    deepInspectorHex: document.getElementById('deepInspectorHex'),
    deepCloseInspectorBtn: document.getElementById('deepCloseInspectorBtn')
  };

  // =========================================================================
  // 1. THREE.JS 3D NETWORK VISUALIZATION
  // =========================================================================
  // Centralized Device-Type Color Mapping & Metadata
  // =========================================================================
  const DEVICE_TYPE_COLORS = {
    'Router':        { name: 'Router', hex: '#00D5FF', int: 0x00d5ff },
    'Switch':        { name: 'Switch', hex: '#4287F5', int: 0x4287f5 },
    'Server':        { name: 'Server', hex: '#A970FF', int: 0xa970ff },
    'Desktop / PC':  { name: 'Desktop / PC', hex: '#42D392', int: 0x42d392 },
    'Laptop':        { name: 'Laptop', hex: '#20B8A8', int: 0x20b8a8 },
    'Mobile device': { name: 'Mobile device', hex: '#FF9F43', int: 0xff9f43 },
    'IoT device':    { name: 'IoT device', hex: '#F4D35E', int: 0xf4d35e },
    'Firewall':      { name: 'Firewall', hex: '#FF4D5A', int: 0xff4d5a },
    'Unknown':       { name: 'Unknown / other', hex: '#8B95A5', int: 0x8b95a5 }
  };

  function normalizeDeviceType(rawType) {
    if (!rawType || typeof rawType !== 'string') return 'Unknown';
    const cleaned = rawType.trim().toLowerCase();
    if (!cleaned || ['unknown', 'unverified', 'other', 'none', 'observed ip endpoint', 'observed l2/l3 node', 'operating-system connection endpoint'].includes(cleaned)) {
      return 'Unknown';
    }
    // Router rule: Gateway, Core Router, Router normalize strictly to Router
    if (cleaned.includes('router') || cleaned.includes('gateway')) {
      return 'Router';
    }
    if (cleaned.includes('switch')) {
      return 'Switch';
    }
    if (cleaned.includes('server')) {
      return 'Server';
    }
    if (cleaned.includes('desktop') || cleaned.includes('workstation') || cleaned.includes('pc')) {
      return 'Desktop / PC';
    }
    if (cleaned.includes('laptop') || cleaned.includes('notebook')) {
      return 'Laptop';
    }
    if (cleaned.includes('mobile') || cleaned.includes('phone') || cleaned.includes('tablet') || cleaned.includes('android') || cleaned.includes('ios')) {
      return 'Mobile device';
    }
    if (cleaned.includes('iot') || cleaned.includes('sensor') || cleaned.includes('camera') || cleaned.includes('smart device')) {
      return 'IoT device';
    }
    if (cleaned.includes('firewall') || cleaned.includes('fw') || cleaned.includes('ngfw')) {
      return 'Firewall';
    }
    return 'Unknown';
  }

  function getDeviceTypeConfig(rawType) {
    const canonical = normalizeDeviceType(rawType);
    return DEVICE_TYPE_COLORS[canonical] || DEVICE_TYPE_COLORS['Unknown'];
  }

  function updateDeviceTypeLegend(nodes) {
    const container = document.getElementById('legendDeviceTypesContainer');
    const countBadge = document.getElementById('legendConnectedCount');
    const count = (nodes && Array.isArray(nodes)) ? nodes.length : 0;
    if (countBadge) {
      countBadge.textContent = `${count} Connected`;
    }
    if (!container) return;

    if (count === 0) {
      container.innerHTML = '<div class="legend-empty-note">Waiting for connected devices...</div>';
      return;
    }

    const typeCounts = new Map();
    nodes.forEach(node => {
      const devType = normalizeDeviceType(node.device_type || node.role);
      typeCounts.set(devType, (typeCounts.get(devType) || 0) + 1);
    });

    let html = '';
    const sortedTypes = Array.from(typeCounts.entries()).sort((a, b) => b[1] - a[1]);

    sortedTypes.forEach(([devType, c]) => {
      const cfg = DEVICE_TYPE_COLORS[devType] || DEVICE_TYPE_COLORS['Unknown'];
      html += `
        <div class="legend-row">
          <span class="legend-dot" style="background-color: ${cfg.hex}; box-shadow: 0 0 6px ${cfg.hex}88;"></span>
          <span class="legend-label">${cfg.name}</span>
          <span class="legend-count-pill">${c}</span>
        </div>
      `;
    });

    container.innerHTML = html;
  }

  // Expose for verification and browser inspector
  if (typeof window !== 'undefined') {
    window.SOC_VISUALIZATION = {
      DEVICE_TYPE_COLORS,
      normalizeDeviceType,
      getDeviceTypeConfig,
      updateDeviceTypeLegend
    };
  }

  let scene, camera, renderer, controls, raycaster, mouse;
  const nodeMeshes = new Map();
  const edgeMeshes = new Map();
  const alertRings = [];
  const edgeParticles = [];
  let isHoveringNode = false;
  let hoveredNode = null;

  function initThreeJs() {
    if (!dom.threeJsCanvas || typeof THREE === 'undefined') {
      console.warn('Three.js not loaded or canvas missing');
      return;
    }

    const width = dom.threejsViewportContainer.clientWidth || 800;
    const height = dom.threejsViewportContainer.clientHeight || 600;

    // Scene
    scene = new THREE.Scene();
    scene.background = new THREE.Color(0x070b14);
    scene.fog = new THREE.FogExp2(0x070b14, 0.0018);

    // Camera
    camera = new THREE.PerspectiveCamera(45, width / height, 1, 3000);
    camera.position.set(0, 160, 420);

    // Renderer
    renderer = new THREE.WebGLRenderer({
      canvas: dom.threeJsCanvas,
      antialias: true,
      alpha: true,
      powerPreference: 'high-performance'
    });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    // OrbitControls
    if (typeof THREE.OrbitControls !== 'undefined') {
      controls = new THREE.OrbitControls(camera, renderer.domElement);
      controls.enableDamping = true;
      controls.dampingFactor = 0.06;
      controls.maxDistance = 900;
      controls.minDistance = 60;
      controls.maxPolarAngle = Math.PI / 2 + 0.1;
      controls.target.set(0, 0, 0);
    }

    // Lights
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.55);
    scene.add(ambientLight);

    const dirLight1 = new THREE.DirectionalLight(0x38bdf8, 1.2);
    dirLight1.position.set(200, 300, 200);
    scene.add(dirLight1);

    const dirLight2 = new THREE.DirectionalLight(0xef4444, 0.7);
    dirLight2.position.set(-200, -100, -200);
    scene.add(dirLight2);

    const centerPointLight = new THREE.PointLight(0x0284c7, 2, 600);
    centerPointLight.position.set(0, 50, 0);
    scene.add(centerPointLight);

    // Subtle Ground Grid
    const grid = new THREE.GridHelper(700, 35, 0x1e293b, 0x0f172a);
    grid.position.y = -180;
    scene.add(grid);

    // Spatial Starfield
    createSpatialDust();

    // Raycaster for mouse interaction
    raycaster = new THREE.Raycaster();
    mouse = new THREE.Vector2();

    // Event Listeners for 3D Viewport
    window.addEventListener('resize', onWindowResize);
    dom.threeJsCanvas.addEventListener('mousemove', onCanvasMouseMove);
    dom.threeJsCanvas.addEventListener('click', onCanvasClick);

    // Start 3D Animation Loop
    animateThreeJs();
  }

  function createSpatialDust() {
    const particleCount = 400;
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);
    const colors = new Float32Array(particleCount * 3);

    for (let i = 0; i < particleCount; i++) {
      positions[i * 3] = (Math.random() - 0.5) * 1200;
      positions[i * 3 + 1] = (Math.random() - 0.5) * 800;
      positions[i * 3 + 2] = (Math.random() - 0.5) * 1200;

      colors[i * 3] = 0.15 + Math.random() * 0.2;
      colors[i * 3 + 1] = 0.4 + Math.random() * 0.4;
      colors[i * 3 + 2] = 0.7 + Math.random() * 0.3;
    }

    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    const material = new THREE.PointsMaterial({
      size: 2.2,
      vertexColors: true,
      transparent: true,
      opacity: 0.6
    });

    const dustParticles = new THREE.Points(geometry, material);
    scene.add(dustParticles);
  }

  function onWindowResize() {
    if (!camera || !renderer || !dom.threejsViewportContainer) return;
    const width = dom.threejsViewportContainer.clientWidth;
    const height = dom.threejsViewportContainer.clientHeight;
    camera.aspect = width / height;
    camera.updateProjectionMatrix();
    renderer.setSize(width, height);
  }

  function onCanvasMouseMove(event) {
    const rect = dom.threeJsCanvas.getBoundingClientRect();
    mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
    mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;

    raycaster.setFromCamera(mouse, camera);
    const interactiveMeshes = Array.from(nodeMeshes.values()).map(n => n.mesh);
    const intersects = raycaster.intersectObjects(interactiveMeshes);

    if (intersects.length > 0) {
      dom.threeJsCanvas.style.cursor = 'pointer';
      const hitMesh = intersects[0].object;
      const nodeData = hitMesh.userData;

      hoveredNode = nodeData;
      isHoveringNode = true;

      dom.threeJsTooltip.style.display = 'block';
      dom.threeJsTooltip.style.left = `${event.clientX - rect.left}px`;
      dom.threeJsTooltip.style.top = `${event.clientY - rect.top - 15}px`;
      const canonicalType = normalizeDeviceType(nodeData.device_type || nodeData.role);
      dom.threeJsTooltip.innerHTML = `
        <span class="tooltip-ip">${nodeData.ip}</span>
        <span class="tooltip-role">${nodeData.label || nodeData.ip} (${canonicalType})</span>
      `;
    } else {
      dom.threeJsCanvas.style.cursor = 'default';
      isHoveringNode = false;
      hoveredNode = null;
      dom.threeJsTooltip.style.display = 'none';
    }
  }

  function onCanvasClick() {
    if (hoveredNode) {
      selectNodeIn3D(hoveredNode);
    }
  }

  function selectNodeIn3D(nodeData) {
    state.selectedNodeId = nodeData.id;

    // Populate Floating Node Inspector with strictly verified attributes
    const canonicalType = normalizeDeviceType(nodeData.device_type || nodeData.role);
    dom.insRolePill.textContent = canonicalType !== 'Unknown' ? canonicalType : (nodeData.role || 'Observed Endpoint');
    dom.insCatPill.textContent = (nodeData.category || 'Normal').toUpperCase();
    dom.insCatPill.className = `inspector-cat-pill cat-${(nodeData.category || 'normal').toLowerCase()}`;

    dom.insNodeLabel.textContent = nodeData.label || nodeData.ip;
    dom.insNodeIp.textContent = nodeData.ip || 'Unavailable';
    dom.insNodeDesc.textContent = nodeData.description || 'Verified endpoint observed through network traffic.';

    // Rule 4 & 5: Never invent fake MAC addresses, OS, or risk scores
    dom.insNodeMac.textContent = nodeData.mac || 'Unavailable';
    dom.insNodeOs.textContent = nodeData.os || 'Unavailable';
    dom.insNodeSessions.textContent = nodeData.active_connections !== undefined ? `${nodeData.active_connections} flows` : 'Unavailable';
    dom.insNodeRisk.textContent = nodeData.risk_score !== undefined ? `${nodeData.risk_score} / 100` : 'Unavailable';

    dom.threeNodeInspector.style.display = 'block';

    dom.insFilterLogsBtn.onclick = () => {
      dom.logSearchInput.value = nodeData.ip;
      state.searchTerm = nodeData.ip;
      fetchSocThreatLogs();
    };

    if (controls) {
      const pos = nodeData.pos || [0, 0, 0];
      smoothPanCamera(new THREE.Vector3(pos[0], pos[1], pos[2]));
    }
  }

  function smoothPanCamera(targetPos) {
    if (!controls) return;
    const startTarget = controls.target.clone();
    const duration = 600;
    const startTime = performance.now();

    function updatePan(now) {
      const elapsed = now - startTime;
      const progress = Math.min(1, elapsed / duration);
      const ease = 0.5 - Math.cos(progress * Math.PI) / 2;

      controls.target.lerpVectors(startTarget, targetPos, ease);

      if (progress < 1) {
        requestAnimationFrame(updatePan);
      }
    }
    requestAnimationFrame(updatePan);
  }

  function clear3DTopologyMeshes() {
    nodeMeshes.forEach(val => {
      if (val.mesh) scene.remove(val.mesh);
      if (val.connRingMesh) scene.remove(val.connRingMesh);
    });
    nodeMeshes.clear();

    edgeMeshes.forEach(({ line }) => scene.remove(line));
    edgeMeshes.clear();

    alertRings.forEach(ring => scene.remove(ring.mesh));
    alertRings.length = 0;

    edgeParticles.forEach(ep => scene.remove(ep.mesh));
    edgeParticles.length = 0;

    updateDeviceTypeLegend([]);
  }

  function build3DTopology(data) {
    if (!scene) return;
    state.topologyData = data || { nodes: [], edges: [] };
    const allNodes = data && data.nodes ? data.nodes : [];
    // Strict Connected-Device Policy: render only nodes whose is_connected is explicitly true
    const nodes = allNodes.filter(n => n && n.is_connected === true);
    const connectedNodeIds = new Set(nodes.map(n => n.id));

    // Edges strictly between connected nodes
    const allEdges = data && data.edges ? data.edges : [];
    const edges = allEdges.filter(e => connectedNodeIds.has(e.source) && connectedNodeIds.has(e.target));

    // Empty State Check: no live devices currently connected
    if (nodes.length === 0) {
      clear3DTopologyMeshes();
      if (dom.threeJsEmptyState) {
        dom.threeJsEmptyState.style.display = 'flex';
        const title = dom.threeJsEmptyState.querySelector('.empty-title');
        if (title) title.textContent = 'No connected devices detected';
        const desc = dom.threeJsEmptyState.querySelector('.empty-desc');
        if (desc) desc.textContent = 'No live devices have transmitted verified packets within the 60s recency window. Disconnected and historical endpoints are quarantined.';
      }
      dom.hudNodesOnline.textContent = '0 CONNECTED DEVICES';
      dom.hudEdgesActive.textContent = '0 ACTIVE LINKS';
      dom.hudThreatNodes.textContent = '0 THREAT NODES';
      if (dom.threeNodeInspector) {
        dom.threeNodeInspector.style.display = 'none';
      }
      updateDeviceTypeLegend([]);
      return;
    }

    // Connected devices present: hide empty state overlay
    if (dom.threeJsEmptyState) {
      dom.threeJsEmptyState.style.display = 'none';
    }

    // Update HUD counters to reflect connected devices accurately
    dom.hudNodesOnline.textContent = `${nodes.length} CONNECTED DEVICES`;
    dom.hudEdgesActive.textContent = `${edges.length} ACTIVE LINKS`;

    const threatCount = nodes.filter(n => n.category === 'Suspicious' || n.category === 'Malicious').length;
    dom.hudThreatNodes.textContent = `${threatCount} THREAT NODES`;

    // Update dynamic legend with current connected devices and counts
    updateDeviceTypeLegend(nodes);

    // 1. Reconcile Nodes: remove disconnected or expired nodes from scene
    nodeMeshes.forEach((val, id) => {
      if (!connectedNodeIds.has(id)) {
        scene.remove(val.mesh);
        if (val.connRingMesh) scene.remove(val.connRingMesh);
        nodeMeshes.delete(id);
      }
    });

    // Reconcile Alert Rings: remove orphaned rings when nodes disconnect
    for (let i = alertRings.length - 1; i >= 0; i--) {
      const ring = alertRings[i];
      if (!ring.nodeId || !connectedNodeIds.has(ring.nodeId)) {
        scene.remove(ring.mesh);
        alertRings.splice(i, 1);
      }
    }

    nodes.forEach(node => {
      const devType = normalizeDeviceType(node.device_type || node.role);
      const typeConfig = getDeviceTypeConfig(devType);

      if (nodeMeshes.has(node.id)) {
        const item = nodeMeshes.get(node.id);
        const prevType = item.deviceType;
        item.node = node;
        item.mesh.userData = node;

        // Reconcile device-type material when reported device type changes
        if (prevType !== devType) {
          item.mesh.material.color.setHex(typeConfig.int);
          item.mesh.material.emissive.setHex(typeConfig.int);
          item.deviceType = devType;
        }

        // Reconcile threat alert ring independently without modifying primary device-type color
        const hasThreat = node.has_alert || node.category === 'Suspicious' || node.category === 'Malicious';
        const ringIdx = alertRings.findIndex(r => r.nodeId === node.id);

        if (hasThreat) {
          const ringColor = node.category === 'Malicious' ? 0xef4444 : 0xf59e0b;
          if (ringIdx >= 0) {
            alertRings[ringIdx].mesh.material.color.setHex(ringColor);
          } else {
            const size = item.size || 10;
            const ringGeo = new THREE.RingGeometry(size * 1.45, size * 1.75, 32);
            const ringMat = new THREE.MeshBasicMaterial({
              color: ringColor,
              side: THREE.DoubleSide,
              transparent: true,
              opacity: 0.85
            });
            const ringMesh = new THREE.Mesh(ringGeo, ringMat);
            ringMesh.position.copy(item.mesh.position);
            ringMesh.rotation.x = Math.PI / 2;
            scene.add(ringMesh);
            alertRings.push({ mesh: ringMesh, baseSize: size * 1.45, scale: 1, nodeId: node.id });
          }
        } else if (ringIdx >= 0) {
          scene.remove(alertRings[ringIdx].mesh);
          alertRings.splice(ringIdx, 1);
        }

        return;
      }

      // Create new 3D Node Mesh strictly colored by device type
      const color = typeConfig.int;
      let size = 10;
      let geometry;

      switch (devType) {
        case 'Router':
          size = 13;
          geometry = new THREE.IcosahedronGeometry(size, 1);
          break;
        case 'Switch':
          size = 12;
          geometry = new THREE.OctahedronGeometry(size, 0);
          break;
        case 'Server':
          size = 11;
          geometry = new THREE.CylinderGeometry(size * 0.9, size * 0.9, size * 1.4, 16);
          break;
        case 'Desktop / PC':
          size = 11;
          geometry = new THREE.BoxGeometry(size * 1.2, size * 1.2, size * 1.2);
          break;
        case 'Laptop':
          size = 10;
          geometry = new THREE.BoxGeometry(size * 1.4, size * 0.4, size * 1.0);
          break;
        case 'Mobile device':
          size = 9;
          geometry = new THREE.BoxGeometry(size * 0.7, size * 1.4, size * 0.35);
          break;
        case 'IoT device':
          size = 8;
          geometry = new THREE.OctahedronGeometry(size, 0);
          break;
        case 'Firewall':
          size = 12;
          geometry = new THREE.DodecahedronGeometry(size, 0);
          break;
        case 'Unknown':
        default:
          size = 9;
          geometry = new THREE.SphereGeometry(size, 16, 16);
          break;
      }

      const material = new THREE.MeshStandardMaterial({
        color: color,
        roughness: 0.25,
        metalness: 0.65,
        emissive: color,
        emissiveIntensity: 0.25
      });

      const mesh = new THREE.Mesh(geometry, material);
      const pos = node.pos || [0, 0, 0];
      mesh.position.set(pos[0], pos[1], pos[2]);
      mesh.userData = node;
      scene.add(mesh);

      // Connectivity indicator: subtle ring beneath node base
      const connRingGeo = new THREE.RingGeometry(size * 1.15, size * 1.28, 32);
      const connRingMat = new THREE.MeshBasicMaterial({
        color: 0x00d5ff,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.35
      });
      const connRingMesh = new THREE.Mesh(connRingGeo, connRingMat);
      connRingMesh.position.copy(mesh.position);
      connRingMesh.position.y -= size * 0.55;
      connRingMesh.rotation.x = Math.PI / 2;
      scene.add(connRingMesh);

      // Pulsing alert ring for high-threat or flagged nodes (separate secondary indicator)
      if (node.has_alert || node.category === 'Suspicious' || node.category === 'Malicious') {
        const ringGeo = new THREE.RingGeometry(size * 1.45, size * 1.75, 32);
        const ringMat = new THREE.MeshBasicMaterial({
          color: node.category === 'Malicious' ? 0xef4444 : 0xf59e0b,
          side: THREE.DoubleSide,
          transparent: true,
          opacity: 0.85
        });
        const ringMesh = new THREE.Mesh(ringGeo, ringMat);
        ringMesh.position.copy(mesh.position);
        ringMesh.rotation.x = Math.PI / 2;
        scene.add(ringMesh);
        alertRings.push({ mesh: ringMesh, baseSize: size * 1.45, scale: 1, nodeId: node.id });
      }

      nodeMeshes.set(node.id, { mesh, node, deviceType: devType, size, connRingMesh });
    });

    // 2. Reconcile Edges
    const activeEdgeIds = new Set(edges.map(e => e.id));
    edgeMeshes.forEach((val, id) => {
      if (!activeEdgeIds.has(id)) {
        scene.remove(val.line);
        edgeMeshes.delete(id);
      }
    });

    // Clean orphaned edge particles
    for (let i = edgeParticles.length - 1; i >= 0; i--) {
      const ep = edgeParticles[i];
      if (!ep.edgeId || !activeEdgeIds.has(ep.edgeId)) {
        scene.remove(ep.mesh);
        edgeParticles.splice(i, 1);
      }
    }

    edges.forEach(edge => {
      if (edgeMeshes.has(edge.id)) return;

      const srcNode = nodeMeshes.get(edge.source);
      const dstNode = nodeMeshes.get(edge.target);
      if (!srcNode || !dstNode) return;

      const p1 = srcNode.mesh.position;
      const p2 = dstNode.mesh.position;

      const lineGeo = new THREE.BufferGeometry().setFromPoints([p1, p2]);
      let lineColor = 0x1e293b;
      let lineOpacity = 0.35;

      if (edge.status === 'Malicious') {
        lineColor = 0xef4444;
        lineOpacity = 0.8;
      } else if (edge.status === 'Suspicious') {
        lineColor = 0xf59e0b;
        lineOpacity = 0.65;
      } else {
        lineColor = 0x06b6d4;
        lineOpacity = 0.3;
      }

      const lineMat = new THREE.LineBasicMaterial({
        color: lineColor,
        transparent: true,
        opacity: lineOpacity,
        linewidth: edge.status === 'Malicious' ? 2 : 1
      });

      const line = new THREE.Line(lineGeo, lineMat);
      line.userData = edge;
      scene.add(line);
      edgeMeshes.set(edge.id, { line, edge, p1, p2 });

      // Particle pulse traversing edge
      const particleMat = new THREE.MeshBasicMaterial({
        color: edge.status === 'Malicious' ? 0xff4d4d : (edge.status === 'Suspicious' ? 0xfbbf24 : 0x38bdf8)
      });
      const particleGeo = new THREE.SphereGeometry(2.2, 8, 8);
      const particle = new THREE.Mesh(particleGeo, particleMat);
      scene.add(particle);

      edgeParticles.push({
        mesh: particle,
        p1: p1,
        p2: p2,
        progress: Math.random(),
        speed: 0.006 + Math.random() * 0.008,
        edgeId: edge.id
      });
    });

    applyThreatCategoryFilter(state.filterCategory);
  }

  function applyThreatCategoryFilter(category) {
    state.filterCategory = category;

    document.querySelectorAll('.view-chip').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.filter === category);
    });

    nodeMeshes.forEach(({ mesh, node }) => {
      if (category === 'ALL') {
        mesh.visible = true;
      } else if (category === 'NORMAL') {
        mesh.visible = node.category === 'Normal';
      } else if (category === 'SUSPICIOUS') {
        mesh.visible = node.category === 'Suspicious';
      } else if (category === 'MALICIOUS') {
        mesh.visible = node.category === 'Malicious';
      }
    });

    edgeMeshes.forEach(({ line, p1, p2 }) => {
      const srcVisible = scene.children.some(c => c.position && c.position.distanceTo(p1) < 0.1 && c.visible);
      const dstVisible = scene.children.some(c => c.position && c.position.distanceTo(p2) < 0.1 && c.visible);
      line.visible = srcVisible && dstVisible;
    });
  }

  function animateThreeJs() {
    requestAnimationFrame(animateThreeJs);

    if (controls) {
      if (state.autoRotate3D) {
        controls.autoRotate = true;
        controls.autoRotateSpeed = 1.0;
      } else {
        controls.autoRotate = false;
      }
      controls.update();
    }

    const time = performance.now() * 0.002;
    alertRings.forEach(item => {
      const scale = 1 + Math.sin(time * 3) * 0.25;
      item.mesh.scale.set(scale, scale, 1);
      item.mesh.material.opacity = 0.5 + Math.sin(time * 3) * 0.4;
      item.mesh.rotation.z += 0.01;
    });

    edgeParticles.forEach(ep => {
      ep.progress += ep.speed;
      if (ep.progress > 1) ep.progress = 0;
      ep.mesh.position.lerpVectors(ep.p1, ep.p2, ep.progress);
    });

    nodeMeshes.forEach(({ mesh, node }) => {
      if (node.has_alert) {
        mesh.rotation.y += 0.015;
      }
    });

    if (renderer && scene && camera) {
      renderer.render(scene, camera);
    }
  }

  // =========================================================================
  // 2. TIME-SERIES TRAFFIC CHART (CANVAS 2D)
  // =========================================================================
  function renderTimeSeriesChart(samples) {
    if (!dom.trafficTimeSeriesCanvas) return;
    const canvas = dom.trafficTimeSeriesCanvas;
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;

    ctx.clearRect(0, 0, width, height);

    // Rule 6: Plot measured traffic only. When empty, render clean waiting state
    if (!samples || samples.length === 0) {
      ctx.fillStyle = '#64748b';
      ctx.font = '11px JetBrains Mono, monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('Waiting for real traffic observations...', width / 2, height / 2);

      // Provenance badge
      if (state.currentMode === 'pcap') {
        ctx.fillStyle = '#38bdf8';
        ctx.font = '9px JetBrains Mono, monospace';
        ctx.fillText('[HISTORICAL PCAP MODE]', width / 2, height / 2 + 18);
      } else if (state.currentMode === 'simulation') {
        ctx.fillStyle = '#a855f7';
        ctx.font = '9px JetBrains Mono, monospace';
        ctx.fillText('[SIMULATION MODE - TEST ONLY]', width / 2, height / 2 + 18);
      }
      return;
    }

    // Determine max PPS
    let maxPps = 10;
    samples.forEach(s => {
      const tot = s.total_pps || (s.normal_pps + s.suspicious_pps + s.malicious_pps);
      if (tot > maxPps) maxPps = tot;
    });
    maxPps = Math.ceil(maxPps * 1.15);

    const padL = 8;
    const padR = 8;
    const padT = 12;
    const padB = 10;
    const plotW = width - padL - padR;
    const plotH = height - padT - padB;

    const stepX = plotW / Math.max(1, samples.length - 1);
    const getY = (val) => padT + plotH - ((val || 0) / maxPps) * plotH;

    // Gridlines
    ctx.strokeStyle = '#1e293b';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 3; i++) {
      const y = padT + (plotH / 3) * i;
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(width - padR, y);
      ctx.stroke();
    }

    // Mode watermark
    if (state.currentMode === 'pcap') {
      ctx.fillStyle = 'rgba(56, 189, 248, 0.2)';
      ctx.font = '10px JetBrains Mono, monospace';
      ctx.textAlign = 'right';
      ctx.fillText('HISTORICAL PCAP', width - padR - 4, padT + 12);
    } else if (state.currentMode === 'simulation') {
      ctx.fillStyle = 'rgba(168, 85, 247, 0.2)';
      ctx.font = '10px JetBrains Mono, monospace';
      ctx.textAlign = 'right';
      ctx.fillText('SIMULATION', width - padR - 4, padT + 12);
    }

    // 1. Normal Traffic Line (Green)
    ctx.beginPath();
    samples.forEach((s, i) => {
      const x = padL + i * stepX;
      const y = getY(s.normal_pps);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = '#10b981';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Area fill
    ctx.lineTo(padL + (samples.length - 1) * stepX, padT + plotH);
    ctx.lineTo(padL, padT + plotH);
    ctx.closePath();
    ctx.fillStyle = 'rgba(16, 185, 129, 0.08)';
    ctx.fill();

    // 2. Suspicious Traffic Line (Amber)
    ctx.beginPath();
    samples.forEach((s, i) => {
      const x = padL + i * stepX;
      const y = getY(s.suspicious_pps);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = '#f59e0b';
    ctx.lineWidth = 2;
    ctx.stroke();

    // 3. Malicious Traffic Line (Red)
    ctx.beginPath();
    samples.forEach((s, i) => {
      const x = padL + i * stepX;
      const y = getY(s.malicious_pps);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = '#ef4444';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Latest active point indicator
    const lastIdx = samples.length - 1;
    const lastX = padL + lastIdx * stepX;
    const lastNormY = getY(samples[lastIdx].normal_pps);
    ctx.beginPath();
    ctx.arc(lastX, lastNormY, 3.5, 0, Math.PI * 2);
    ctx.fillStyle = '#10b981';
    ctx.fill();
  }

  // Sequence tracking to prevent delayed / out-of-order responses from overwriting newer state
  let healthReqSeq = 0;
  let overviewReqSeq = 0;
  let topologyReqSeq = 0;
  let feedReqSeq = 0;
  let logsReqSeq = 0;

  // =========================================================================
  // 3. CAPTURE HEALTH & PROVENANCE (Phase 5: Section 1)
  // =========================================================================
  async function fetchCaptureHealth() {
    const seq = ++healthReqSeq;
    try {
      const res = await fetch('/api/capture/health');
      if (seq < healthReqSeq) return; // Discard stale response
      if (!res.ok) {
        setHealthState('Capture error', 'Failed to communicate with capture health endpoint.');
        return;
      }
      const data = await res.json();
      if (seq < healthReqSeq) return; // Discard stale response
      state.captureHealth = data;
      state.isCapturing = Boolean(data.is_capturing);

      // Selected interface
      const ifaceName = data.selected_interface_name || data.selected_interface || 'Auto-detecting...';
      dom.healthInterfaceText.textContent = ifaceName;

      // Capture backend
      dom.healthBackendText.textContent = data.capture_backend || 'Unavailable';

      // Actual packet count
      const pktCount = data.actual_packets_captured !== undefined ? data.actual_packets_captured : 0;
      dom.healthPacketCount.textContent = pktCount.toLocaleString();

      // Last captured timestamp
      dom.healthLastSeen.textContent = data.last_packet_timestamp || 'Not yet observed';

      // Operating mode
      if (data.capture_mode) {
        state.currentMode = data.capture_mode;
        if (dom.systemModeSelect && dom.systemModeSelect.value !== data.capture_mode) {
          dom.systemModeSelect.value = data.capture_mode;
        }
        updateSourcePill(data.capture_mode, data.selected_interface_name);
      }

      // Determine state strictly according to Section 1 rules:
      // Clear states: Initializing, Capturing real packets, No packets observed, Capture error, Insufficient permissions, Stopped
      const npcapDiag = data.npcap_diagnostics || {};
      const statusRaw = (data.capture_status || '').toUpperCase();

      if (statusRaw === 'INSUFFICIENT PERMISSIONS') {
        setHealthState('Insufficient permissions', data.recovery_instruction || 'Administrator privileges required for raw packet sniffing.');
      } else if (statusRaw === 'CAPTURE ERROR' || !npcapDiag.installed) {
        const errorMsg = data.last_error || 'Npcap packet driver not installed on host.';
        const recMsg = data.recovery_instruction || 'Install Npcap in "WinPcap API-compatible Mode" from npcap.com, then restart the application as Administrator.';
        setHealthState('Capture error', `${errorMsg} — ${recMsg}`);
      } else if (statusRaw === 'STOPPED' || !data.is_capturing) {
        setHealthState('Stopped', null);
      } else if (statusRaw === 'INITIALIZING') {
        setHealthState('Initializing', null);
      } else if (data.is_capturing && pktCount > 0) {
        // ONLY display 'Capturing real packets' after the engine confirms genuine packets have actually been received
        setHealthState('Capturing real packets', null);
      } else if (data.is_capturing && pktCount === 0) {
        setHealthState('No packets observed', null);
      } else {
        setHealthState(data.capture_status || 'Initializing', null);
      }

    } catch (err) {
      console.warn('Error fetching /api/capture/health:', err);
      setHealthState('Capture error', 'Network connection to backend failed.');
    }
  }

  function setHealthState(stateText, diagnosticMessage) {
    dom.healthStatusText.textContent = stateText.toUpperCase();
    if (dom.emptyCaptureStatusTag) {
      dom.emptyCaptureStatusTag.textContent = `Status: ${stateText.toUpperCase()}`;
    }

    // Reset status dot
    dom.healthStatusDot.className = 'health-dot';

    switch (stateText) {
      case 'Capturing real packets':
        dom.healthStatusDot.classList.add('dot-active');
        hideDiagnosticStrip();
        break;
      case 'No packets observed':
      case 'Initializing':
        dom.healthStatusDot.classList.add('dot-warning');
        hideDiagnosticStrip();
        break;
      case 'Stopped':
        dom.healthStatusDot.classList.add('dot-stopped');
        hideDiagnosticStrip();
        break;
      case 'Capture error':
      case 'Insufficient permissions':
      default:
        dom.healthStatusDot.classList.add('dot-error');
        if (diagnosticMessage) {
          showDiagnosticStrip(stateText, diagnosticMessage);
        } else {
          hideDiagnosticStrip();
        }
        break;
    }
  }

  function showDiagnosticStrip(title, message) {
    if (!dom.healthDiagnosticStrip) return;
    dom.healthDiagnosticStrip.style.display = 'flex';
    dom.healthDiagnosticTitle.textContent = title;
    dom.healthDiagnosticMsg.textContent = message;
  }

  function hideDiagnosticStrip() {
    if (!dom.healthDiagnosticStrip) return;
    dom.healthDiagnosticStrip.style.display = 'none';
  }

  function updateSourcePill(mode, interfaceName) {
    if (!dom.sourceTypePill || !dom.sourceTextLabel) return;

    dom.sourceTypePill.className = 'source-type-pill';

    if (mode === 'live') {
      dom.sourceTypePill.textContent = 'LIVE';
      dom.sourceTypePill.classList.add('pill-live');
      dom.sourceTextLabel.textContent = interfaceName ? interfaceName.split('(')[0].trim() : 'Live Packets';
    } else if (mode === 'pcap') {
      dom.sourceTypePill.textContent = 'HISTORICAL PCAP';
      dom.sourceTypePill.classList.add('pill-pcap');
      dom.sourceTextLabel.textContent = 'Offline Trace';
    } else if (mode === 'simulation') {
      dom.sourceTypePill.textContent = 'SIMULATION';
      dom.sourceTypePill.classList.add('pill-sim');
      dom.sourceTextLabel.textContent = 'Quarantined Test';
    } else if (mode === 'connection_metadata') {
      dom.sourceTypePill.textContent = 'SOCKET METADATA';
      dom.sourceTypePill.classList.add('pill-conn');
      dom.sourceTextLabel.textContent = 'Host Sockets (netstat)';
    }
  }

  // =========================================================================
  // 4. NETWORK INTERFACE SELECTION (Phase 5: Section 2)
  // =========================================================================
  async function fetchInterfaces() {
    try {
      const res = await fetch('/api/capture/interfaces');
      if (!res.ok) return;
      const data = await res.json();
      const ifaces = data.interfaces || [];

      dom.systemInterfaceSelect.innerHTML = '';

      if (ifaces.length === 0) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = 'No host interfaces discovered';
        dom.systemInterfaceSelect.appendChild(opt);
        return;
      }

      ifaces.forEach(iface => {
        const opt = document.createElement('option');
        opt.value = iface.id;
        const ipLabel = iface.ip ? ` [${iface.ip}]` : '';
        opt.textContent = `${iface.name}${ipLabel}`;
        if (state.selectedInterfaceId && state.selectedInterfaceId === iface.id) {
          opt.selected = true;
        }
        dom.systemInterfaceSelect.appendChild(opt);
      });

      // Select first interface if none chosen
      if (!state.selectedInterfaceId && ifaces.length > 0) {
        state.selectedInterfaceId = ifaces[0].id;
      }

    } catch (err) {
      console.warn('Error fetching network interfaces:', err);
    }
  }

  // =========================================================================
  // 5. OPERATING MODE SWITCHING (Phase 5: Section 3)
  // =========================================================================
  async function switchOperatingMode(newMode, pcapPath = null) {
    const prevMode = state.currentMode;
    try {
      const payload = { mode: newMode };
      if (pcapPath) payload.pcap_path = pcapPath;
      if (state.selectedInterfaceId) payload.interface_id = state.selectedInterfaceId;

      const res = await fetch('/api/mode/select', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        const detail = errJson.detail || `Server rejected mode change to ${newMode}.`;
        alert(`Mode Switch Rejected: ${detail}`);
        // Reset selector back to confirmed previous mode
        dom.systemModeSelect.value = prevMode;
        return false;
      }

      state.currentMode = newMode;

      // Rule 4: Immediately clear client-side buffers to guarantee visual isolation
      clear3DTopologyMeshes();
      if (dom.threeJsEmptyState) dom.threeJsEmptyState.style.display = 'flex';
      state.threatLogs = [];
      state.timeSeriesData = [];
      renderThreatLogsFeed([]);
      renderTimeSeriesChart([]);

      // Refetch all components immediately
      await fetchCaptureHealth();
      await fetchSocOverview();
      await fetchSocTopology();
      await fetchSocThreatLogs();
      if (state.activeView === 'modelDeepDiveView') {
        await fetchLiveFeed();
      }
      return true;

    } catch (err) {
      console.error('Mode switch failed:', err);
      alert(`Mode switch failed: ${err.message}`);
      dom.systemModeSelect.value = prevMode;
      return false;
    }
  }

  // =========================================================================
  // 6. SOC OVERVIEW & TELEMETRY SYNCHRONIZATION
  // =========================================================================
  async function fetchSocOverview() {
    const seq = ++overviewReqSeq;
    try {
      const res = await fetch('/api/soc/overview');
      if (seq < overviewReqSeq) return; // Discard stale delayed response
      if (!res.ok) {
        handleServerDisconnect();
        return;
      }
      const data = await res.json();
      if (seq < overviewReqSeq) return; // Discard stale delayed response
      state.lastSuccessfulPoll = new Date();

      updateTrafficCounters(data.traffic_counts);
      updateNetworkStats(data.network_stats);
      updateSeverityBreakdown(data.severity_breakdown);
      updateThreatStats(data.threat_stats);
      updateActiveAlert(data.active_alert);

      if (data.time_series) {
        state.timeSeriesData = data.time_series;
        renderTimeSeriesChart(data.time_series);
      }
    } catch (err) {
      console.warn('Error fetching /api/soc/overview:', err);
      handleServerDisconnect();
    }
  }

  function handleServerDisconnect() {
    if (state.lastSuccessfulPoll && (Date.now() - state.lastSuccessfulPoll.getTime() > 6000)) {
      if (dom.sourceTextLabel) {
        dom.sourceTextLabel.textContent = 'Server Disconnected';
      }
      if (dom.headerPulseDot) {
        dom.headerPulseDot.style.background = '#ef4444';
      }
    }
  }

  async function fetchSocTopology() {
    const seq = ++topologyReqSeq;
    try {
      const res = await fetch('/api/soc/topology');
      if (seq < topologyReqSeq) return; // Discard stale delayed response
      if (!res.ok) {
        handleTopologyFetchFailure(`HTTP error ${res.status}`);
        return;
      }
      const data = await res.json();
      if (seq < topologyReqSeq) return; // Discard stale delayed response
      build3DTopology(data);
    } catch (err) {
      console.warn('Error fetching /api/soc/topology:', err);
      handleTopologyFetchFailure(err.message || 'Network fetch failed');
    }
  }

  function handleTopologyFetchFailure(reason) {
    // Ensure API failures do not leave a misleading stale topology on screen
    clear3DTopologyMeshes();
    if (dom.threeJsEmptyState) {
      dom.threeJsEmptyState.style.display = 'flex';
      const title = dom.threeJsEmptyState.querySelector('.empty-title');
      if (title) title.textContent = 'Topology Telemetry Offline';
      const desc = dom.threeJsEmptyState.querySelector('.empty-desc');
      if (desc) desc.textContent = `Unable to retrieve verified topology from backend (${reason}). Topology cleared to prevent stale rendering.`;
    }
    if (dom.hudNodesOnline) dom.hudNodesOnline.textContent = '0 CONNECTED DEVICES';
    if (dom.hudEdgesActive) dom.hudEdgesActive.textContent = '0 ACTIVE LINKS';
    if (dom.hudThreatNodes) dom.hudThreatNodes.textContent = '0 THREAT NODES';
  }

  async function fetchSocThreatLogs() {
    const seq = ++logsReqSeq;
    try {
      const params = new URLSearchParams();
      if (state.filterSeverity && state.filterSeverity !== 'ALL') {
        params.append('severity', state.filterSeverity);
      }
      if (state.filterStatus && state.filterStatus !== 'ALL') {
        params.append('status', state.filterStatus);
      }
      if (state.searchTerm) {
        params.append('search', state.searchTerm);
      }

      const res = await fetch(`/api/soc/threat-logs?${params.toString()}`);
      if (seq < logsReqSeq) return; // Discard stale delayed response
      if (!res.ok) return;
      const json = await res.json();
      if (seq < logsReqSeq) return; // Discard stale delayed response

      state.threatLogs = json.logs || [];
      dom.threatLogsCountBadge.textContent = `${json.count || 0} Events`;
      renderThreatLogsFeed(state.threatLogs);
    } catch (err) {
      console.warn('Error fetching threat logs:', err);
    }
  }

  // Update Traffic Counters & Bars in Left Panel (Rule 4: strictly real measurements)
  function updateTrafficCounters(counts) {
    if (!counts) return;

    const norm = counts.normal !== undefined ? counts.normal : 0;
    const susp = counts.suspicious !== undefined ? counts.suspicious : 0;
    const mal = counts.malicious !== undefined ? counts.malicious : 0;
    const tot = counts.total !== undefined ? counts.total : 0;

    dom.normalTrafficCount.textContent = norm.toLocaleString();
    dom.suspiciousTrafficCount.textContent = susp.toLocaleString();
    dom.maliciousTrafficCount.textContent = mal.toLocaleString();
    dom.totalTrafficCount.textContent = tot.toLocaleString();

    // Avoid dividing by zero or showing fake percentages
    if (tot === 0) {
      dom.normalTrafficPct.textContent = '0%';
      dom.suspiciousTrafficPct.textContent = '0%';
      dom.maliciousTrafficPct.textContent = '0%';
      dom.normalBarFill.style.width = '0%';
      dom.suspiciousBarFill.style.width = '0%';
      dom.maliciousBarFill.style.width = '0%';
      dom.segNormal.style.width = '0%';
      dom.segSuspicious.style.width = '0%';
      dom.segMalicious.style.width = '0%';
    } else {
      const normPct = counts.normal_pct !== null && counts.normal_pct !== undefined ? counts.normal_pct : 0;
      const suspPct = counts.suspicious_pct !== null && counts.suspicious_pct !== undefined ? counts.suspicious_pct : 0;
      const malPct = counts.malicious_pct !== null && counts.malicious_pct !== undefined ? counts.malicious_pct : 0;

      dom.normalTrafficPct.textContent = `${normPct}%`;
      dom.suspiciousTrafficPct.textContent = `${suspPct}%`;
      dom.maliciousTrafficPct.textContent = `${malPct}%`;
      dom.normalBarFill.style.width = `${normPct}%`;
      dom.suspiciousBarFill.style.width = `${suspPct}%`;
      dom.maliciousBarFill.style.width = `${malPct}%`;
      dom.segNormal.style.width = `${normPct}%`;
      dom.segSuspicious.style.width = `${suspPct}%`;
      dom.segMalicious.style.width = `${malPct}%`;
    }
  }

  // Update Network Stats in Left Panel
  function updateNetworkStats(stats) {
    if (!stats) return;

    dom.leftPacketRate.textContent = stats.packet_rate !== undefined && stats.packet_rate !== null
      ? stats.packet_rate.toFixed(1)
      : 'Unavailable';

    dom.leftBandwidth.textContent = stats.bandwidth_kbps !== undefined && stats.bandwidth_kbps !== null
      ? stats.bandwidth_kbps.toFixed(1)
      : 'Unavailable';

    dom.leftActiveFlows.textContent = stats.active_flows !== undefined && stats.active_flows !== null
      ? stats.active_flows
      : '0';

    dom.leftDataVolume.textContent = stats.total_bytes !== undefined && stats.total_bytes !== null
      ? (stats.total_bytes / 1024).toFixed(1)
      : '0.0';

    if (stats.source_type) {
      updateSourcePill(state.currentMode, stats.data_source);
    }
  }

  function updateSeverityBreakdown(sevs) {
    if (!sevs) return;
    dom.sevCriticalCount.textContent = sevs.Critical || 0;
    dom.sevHighCount.textContent = sevs.High || 0;
    dom.sevMediumCount.textContent = sevs.Medium || 0;
    dom.sevLowCount.textContent = sevs.Low || 0;
    dom.sevInfoCount.textContent = sevs.Informational || 0;
  }

  // Update AI Forecast Box (Rule 7: Strict Gating)
  function updateThreatStats(stats) {
    if (!stats) return;

    const allStages = ['Reconnaissance', 'Scanning', 'Enumeration', 'Exploitation', 'Intrusion'];

    // When prediction is NOT available:
    if (stats.prediction_available === false) {
      dom.leftRiskScore.textContent = '—';
      dom.leftRiskBadge.textContent = 'UNAVAILABLE';
      dom.leftRiskBadge.className = 'risk-level-badge level-unavailable';
      dom.leftConfidencePct.textContent = 'Unavailable';
      dom.leftCurrStage.textContent = '—';
      dom.leftNextStage.textContent = '—';

      const reason = stats.formatted_output || stats.reason || 'Prediction unavailable — insufficient validated real traffic data';
      dom.leftForecastOutput.innerHTML = `<span class="forecast-unavailable-msg">${reason}</span>`;

      // Clear all stage pills
      allStages.forEach(st => {
        const pill = document.getElementById(`pill-${st}`);
        if (pill) pill.className = 'stage-pill';
      });

      // Clear deep dive header
      if (dom.deepCurrStage) dom.deepCurrStage.textContent = '—';
      if (dom.deepNextStage) dom.deepNextStage.textContent = '—';
      if (dom.deepConfVal) dom.deepConfVal.textContent = '—';
      return;
    }

    // When prediction IS available (strictly validated):
    dom.leftRiskScore.textContent = stats.threat_index !== undefined ? stats.threat_index : '—';
    const rLvl = (stats.risk_level || 'LOW').toUpperCase();
    dom.leftRiskBadge.textContent = `${rLvl} RISK`;
    dom.leftConfidencePct.textContent = `${stats.confidence}%`;
    dom.leftCurrStage.textContent = stats.current_stage || '—';
    dom.leftNextStage.textContent = stats.predicted_next_stage || '—';

    dom.leftRiskBadge.className = `risk-level-badge level-${rLvl === 'CRITICAL' ? 'critical' : (rLvl === 'HIGH' ? 'high' : (rLvl === 'MEDIUM' ? 'med' : 'low'))}`;

    allStages.forEach(st => {
      const pill = document.getElementById(`pill-${st}`);
      if (!pill) return;
      pill.className = 'stage-pill';
      if (st === stats.current_stage) {
        pill.classList.add('current');
      } else if (st === stats.predicted_next_stage) {
        pill.classList.add('next-target');
      }
    });

    if (dom.deepCurrStage) dom.deepCurrStage.textContent = stats.current_stage || '—';
    if (dom.deepNextStage) dom.deepNextStage.textContent = stats.predicted_next_stage || '—';
    if (dom.deepConfVal) dom.deepConfVal.textContent = `${stats.confidence}%`;
  }

  // Update Active Security Alert Banner
  function updateActiveAlert(alert) {
    if (!alert) {
      if (dom.mainSecurityAlertBanner) {
        dom.mainSecurityAlertBanner.style.display = 'none';
      }
      state.activeAlertIp = null;
      return;
    }

    state.activeAlertIp = alert.source_ip;
    dom.mainSecurityAlertBanner.style.display = 'block';

    dom.alertBannerSev.textContent = `${(alert.severity || 'HIGH').toUpperCase()} ALERT`;
    dom.alertBannerSev.className = `alert-sev-badge sev-badge-${(alert.severity || 'high').toLowerCase()}`;
    dom.alertBannerStatus.textContent = `STATUS: ${(alert.status || 'NEW').toUpperCase()}`;
    dom.alertBannerTime.textContent = alert.timestamp ? alert.timestamp.split(' ')[1] : 'Recent';
    dom.alertBannerTitle.textContent = `${alert.event_type || 'Anomaly'} (${alert.source_ip})`;
    dom.alertBannerIp.textContent = alert.source_ip;
    dom.alertBannerMsg.innerHTML = `Suspicious host <strong class="highlight-ip">${alert.source_ip}</strong> flagged with: <em>${alert.detection_reason}</em>.`;

    dom.alertBtnInvestigate.onclick = () => {
      const match = state.threatLogs.find(l => l.id === alert.id) || alert;
      openEventDetails(match);
    };

    dom.alertBtnLocate3D.onclick = () => {
      focusIpIn3D(alert.source_ip);
    };

    dom.alertBtnAcknowledge.onclick = async () => {
      await updateThreatLogStatus(alert.id, 'Acknowledged');
      fetchSocThreatLogs();
      fetchSocOverview();
    };
  }

  // Render Threat Event Logs Feed in Right Column
  function renderThreatLogsFeed(logs) {
    if (!dom.threatLogsFeed) return;
    dom.threatLogsFeed.innerHTML = '';

    if (!logs || logs.length === 0) {
      dom.threatLogsFeed.innerHTML = `
        <div style="text-align:center; padding: 20px; color: var(--text-muted); font-size: 0.72rem;">
          No matching threat events observed for active filters.
        </div>
      `;
      return;
    }

    logs.forEach(log => {
      const card = document.createElement('div');
      card.className = `log-entry-card ${state.selectedLogId === log.id ? 'active-selected' : ''}`;
      card.dataset.id = log.id;

      const sevClass = `sev-${(log.severity || 'info').toLowerCase()}`;
      const statusClass = (log.status || 'new').toLowerCase();

      card.innerHTML = `
        <div class="log-entry-top">
          <div class="log-badges-left">
            <span class="log-sev-badge ${sevClass}">${log.severity}</span>
            <span class="log-status-badge ${statusClass}">${log.status}</span>
          </div>
          <span class="log-time">${log.time_ago || (log.timestamp ? log.timestamp.split(' ')[1] : '')}</span>
        </div>
        <div class="log-event-title">${log.event_type}</div>
        <div class="log-ip-flow">
          <span>${log.source_ip}</span>
          <span class="log-arrow">➔</span>
          <span>${log.destination_ip}</span>
        </div>
        <div class="log-reason-snip">${log.detection_reason}</div>
      `;

      card.addEventListener('click', () => {
        openEventDetails(log);
      });

      dom.threatLogsFeed.appendChild(card);
    });
  }

  // Open Event Details Drawer
  function openEventDetails(log) {
    state.selectedLogId = log.id;

    document.querySelectorAll('.log-entry-card').forEach(c => {
      c.classList.toggle('active-selected', c.dataset.id === log.id);
    });

    dom.detailLogIdTitle.textContent = `EVENT DETAILS: ${log.id} (${log.event_type})`;
    dom.eventDetailsDrawer.style.display = 'block';

    const steps = log.investigation_steps || [
      `Review network sockets for host ${log.source_ip}`,
      `Verify firewall egress drop rule for destination ${log.destination_ip}`,
      `Quarantine workstation port on switch`
    ];

    dom.drawerBodyContent.innerHTML = `
      <div class="detail-specs-grid">
        <div class="spec-item"><span class="spec-k">TIMESTAMP</span><span class="spec-v">${log.timestamp || 'Not recorded'}</span></div>
        <div class="spec-item"><span class="spec-k">SEVERITY</span><span class="spec-v" style="color:var(--sev-${(log.severity||'high').toLowerCase()})">${log.severity}</span></div>
        <div class="spec-item"><span class="spec-k">SOURCE</span><span class="spec-v">${log.source_ip} : ${log.sport || 0}</span></div>
        <div class="spec-item"><span class="spec-k">DESTINATION</span><span class="spec-v">${log.destination_ip} : ${log.dport || 0}</span></div>
        <div class="spec-item"><span class="spec-k">PROTOCOL</span><span class="spec-v">${log.proto || 'TCP'}</span></div>
        <div class="spec-item"><span class="spec-k">OBSERVED TRAFFIC</span><span class="spec-v">${log.packet_count ?? '—'} pkts (${log.bytes ?? '—'} B)</span></div>
      </div>

      <div>
        <span class="detail-section-title">DETECTION METHOD & REASON:</span>
        <p style="font-size:0.72rem; color: #ffffff; line-height: 1.4; margin-bottom: 6px;">
          ${log.detection_reason}
        </p>
        <span style="font-size:0.65rem; color:var(--color-accent-light); font-family:var(--font-mono);">Engine: ${log.detection_method || 'Verified Anomaly Detector'}</span>
      </div>

      <div>
        <span class="detail-section-title">RECOMMENDED INVESTIGATION STEPS:</span>
        <ul class="investigation-steps-list">
          ${steps.map((st, i) => `
            <li class="investigation-step-item">
              <span class="step-num">${i + 1}.</span>
              <span>${st}</span>
            </li>
          `).join('')}
        </ul>
      </div>

      <div>
        <span class="detail-section-title">DEFENSIVE MITIGATION:</span>
        <div style="background:var(--bg-card); padding:8px; border-radius:4px; font-size:0.7rem; color:#fca5a5; border:1px solid rgba(239,68,68,0.2);">
          ${log.mitigation || 'Inspect endpoint activity and deploy targeted L4 filter.'}
        </div>
      </div>

      <div class="drawer-status-actions">
        <button id="btnMarkAck" class="soc-mini-btn" style="flex:1;">Acknowledge</button>
        <button id="btnMarkInv" class="soc-mini-btn alert-action-btn" style="flex:1;">Investigate</button>
        <button id="btnMarkRes" class="soc-mini-btn success" style="flex:1;">Resolve</button>
      </div>
    `;

    document.getElementById('btnMarkAck').onclick = () => updateThreatLogStatus(log.id, 'Acknowledged');
    document.getElementById('btnMarkInv').onclick = () => updateThreatLogStatus(log.id, 'Investigating');
    document.getElementById('btnMarkRes').onclick = () => updateThreatLogStatus(log.id, 'Resolved');

    dom.eventDetailsDrawer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  async function updateThreatLogStatus(logId, status) {
    try {
      const res = await fetch(`/api/soc/threat-logs/${logId}/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: status })
      });
      if (res.ok) {
        fetchSocThreatLogs();
        fetchSocOverview();
      }
    } catch (err) {
      console.warn('Error updating status:', err);
    }
  }

  function focusIpIn3D(targetIp) {
    if (!targetIp) {
      alert('No active threat IP to locate in 3D topology.');
      return;
    }
    let found = null;
    nodeMeshes.forEach(({ node }) => {
      if (node.ip === targetIp) found = node;
    });

    if (found) {
      selectNodeIn3D(found);
    } else {
      alert(`IP ${targetIp} is not currently observed in the 3D topology.`);
    }
  }

  // =========================================================================
  // 7. ADVANCED BILSTM MODEL DEEP-DIVE & SENSOR ARRAY
  // =========================================================================
  async function fetchLiveFeed() {
    try {
      const res = await fetch('/api/capture/feed?packet_count=35');
      if (!res.ok) return;
      const data = await res.json();

      state.recentPackets = data.recent_packets || [];
      state.latestPrediction = data.prediction || {};

      if (data.latest_features) {
        renderSensorArray(data.latest_features);
      } else {
        renderEmptySensorArray();
      }

      if (data.prediction && data.prediction.shap) {
        renderShapAttributions(data.prediction.shap);
      }

      if (data.prediction && data.prediction.recommendation) {
        renderDefenses(data.prediction.recommendation);
      }

      if (dom.deepLivePacketTableBody) {
        renderPacketTable(state.recentPackets);
      }
    } catch (err) {
      console.warn('Error fetching live capture feed:', err);
    }
  }

  function renderEmptySensorArray() {
    if (!dom.deepSensorsGrid) return;
    dom.deepSensorsGrid.innerHTML = `
      <div style="grid-column: 1 / -1; text-align: center; padding: 25px; color: var(--text-muted); font-size: 0.8rem;">
        Waiting for sufficient verified flows to populate the 12 sliding-window sensors (T=10 flows required).
      </div>
    `;
  }

  function renderSensorArray(features) {
    if (!dom.deepSensorsGrid) return;
    dom.deepSensorsGrid.innerHTML = '';

    const sensorMeta = {
      conn_frequency: { label: 'CONN FREQUENCY', max: 50, desc: 'Connection starts / sec' },
      packet_rate: { label: 'PACKET RATE', max: 500, desc: 'Total wire packet frequency' },
      dst_ip_fanout: { label: 'DST IP FANOUT', max: 20, desc: 'Unique destinations probed' },
      src_dst_entropy: { label: 'SRC/DST ENTROPY', max: 3.5, desc: 'Endpoint address randomness' },
      port_diversity: { label: 'PORT DIVERSITY', max: 25, desc: 'Target port breadth' },
      well_known_port_ratio: { label: 'STANDARD PORT %', max: 1.0, desc: 'Privileged ports (<1024)' },
      host_sweep_rate: { label: 'HOST SWEEP RATE', max: 5.0, desc: 'Horizontal sweep attempts' },
      icmp_arp_ratio: { label: 'ICMP / ARP RATIO', max: 1.0, desc: 'Diagnostic discovery frames' },
      service_probe_rate: { label: 'SERVICE PROBES', max: 10.0, desc: 'Protocol version handshakes' },
      targeted_query_volume: { label: 'QUERY VOLUME', max: 100, desc: 'Service probe burst rate' },
      iat_jitter: { label: 'IAT JITTER', max: 1.0, desc: 'Packet interval irregularity' },
      burstiness_index: { label: 'BURSTINESS INDEX', max: 20, desc: 'Peak to average burst ratio' }
    };

    Object.keys(features).forEach(key => {
      const val = features[key];
      const meta = sensorMeta[key] || { label: key.toUpperCase(), max: 50, desc: 'Flow sensor metric' };
      const pct = Math.min(100, Math.max(5, (val / meta.max) * 100));

      const box = document.createElement('div');
      box.className = 'sensor-meter-box';
      box.innerHTML = `
        <div class="sensor-header">
          <span class="sensor-name">${meta.label}</span>
          <span class="sensor-val">${typeof val === 'number' ? val.toFixed(2) : val}</span>
        </div>
        <span class="sensor-desc" title="${meta.desc}">${meta.desc}</span>
        <div class="sensor-meter-track">
          <div class="sensor-meter-fill" style="width: ${pct}%;"></div>
        </div>
      `;
      dom.deepSensorsGrid.appendChild(box);
    });
  }

  function renderShapAttributions(shap) {
    if (!shap) return;

    if (dom.deepShapRankingBody && shap.feature_ranking) {
      dom.deepShapRankingBody.innerHTML = '';
      shap.feature_ranking.slice(0, 8).forEach(item => {
        const isPos = item.direction === 'increases_risk';
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><span class="shap-feat-name">${item.feature}</span></td>
          <td>${item.description || ''}</td>
          <td>${item.value !== undefined ? item.value.toFixed(2) : '--'}</td>
          <td><span class="shap-pill ${isPos ? 'pos' : 'neg'}">${isPos ? 'Pushes Next Stage' : 'Suppresses'}</span></td>
          <td style="font-family:var(--font-mono); font-weight:700; color:${isPos ? '#f87171' : '#34d399'}">
            ${isPos ? '+' : ''}${item.attribution.toFixed(4)}
          </td>
        `;
        dom.deepShapRankingBody.appendChild(tr);
      });
    }

    if (dom.deepForceBarsList && shap.feature_ranking) {
      dom.deepForceBarsList.innerHTML = '';
      shap.feature_ranking.slice(0, 7).forEach(item => {
        const isPos = item.direction === 'increases_risk';
        const barWidth = Math.min(100, Math.max(10, item.abs_attribution * 120));

        const row = document.createElement('div');
        row.className = 'force-bar-row';
        row.innerHTML = `
          <span class="force-name">${item.feature}</span>
          <div class="force-track">
            <div class="force-fill ${isPos ? 'pos' : 'neg'}" style="width: ${barWidth}%;"></div>
          </div>
          <span class="force-val">${isPos ? '+' : ''}${item.attribution.toFixed(3)}</span>
        `;
        dom.deepForceBarsList.appendChild(row);
      });
    }
  }

  function renderDefenses(rec) {
    if (!dom.socDefenseList || !rec || !rec.options) return;
    dom.socDefenseList.innerHTML = '';

    rec.options.forEach(opt => {
      const item = document.createElement('div');
      item.className = 'defense-item';
      item.innerHTML = `
        <div class="defense-header">
          <span class="defense-prio-tag">PRIO ${opt.priority}</span>
          <span class="defense-title">${opt.action}</span>
        </div>
        <p class="defense-rationale">${opt.rationale}</p>
      `;
      dom.socDefenseList.appendChild(item);
    });
  }

  function renderPacketTable(packets) {
    if (!dom.deepLivePacketTableBody) return;
    dom.deepLivePacketTableBody.innerHTML = '';
    dom.deepPacketTableCount.textContent = `${packets.length} Packets`;

    if (packets.length === 0) {
      dom.deepLivePacketTableBody.innerHTML = '<tr class="empty-row"><td colspan="8">No packets captured yet.</td></tr>';
      return;
    }

    packets.forEach(p => {
      const tr = document.createElement('tr');
      const protoClass = `proto-${(p.proto || 'tcp').toLowerCase()}`;
      tr.innerHTML = `
        <td>${p.id}</td>
        <td>${p.time_str}</td>
        <td>${p.src_ip}:${p.sport || 0}</td>
        <td>${p.dst_ip}:${p.dport || 0}</td>
        <td><span class="packet-proto-badge ${protoClass}">${p.proto}</span></td>
        <td>${p.length} B</td>
        <td>${p.flags || '--'}</td>
        <td style="color:#ffffff;">${p.info || p.attack_hint || 'Standard packet'}</td>
      `;

      tr.addEventListener('click', () => {
        openPacketDissectionModal(p);
      });

      dom.deepLivePacketTableBody.appendChild(tr);
    });
  }

  function openPacketDissectionModal(pkt) {
    dom.deepInspectorTitle.textContent = `Packet #${pkt.id} [${pkt.proto}] Dissection`;
    dom.deepInspectorDetails.innerHTML = `
      <div class="detail-specs-grid" style="margin-bottom: 10px;">
        <div class="spec-item"><span class="spec-k">TIME</span><span class="spec-v">${pkt.time_str}</span></div>
        <div class="spec-item"><span class="spec-k">PROTOCOL</span><span class="spec-v">${pkt.proto}</span></div>
        <div class="spec-item"><span class="spec-k">SOURCE</span><span class="spec-v">${pkt.src_ip}:${pkt.sport || 0}</span></div>
        <div class="spec-item"><span class="spec-k">DESTINATION</span><span class="spec-v">${pkt.dst_ip}:${pkt.dport || 0}</span></div>
        <div class="spec-item"><span class="spec-k">LENGTH</span><span class="spec-v">${pkt.length} Bytes</span></div>
        <div class="spec-item"><span class="spec-k">FLAGS</span><span class="spec-v">${pkt.flags || 'None'}</span></div>
      </div>
      <p style="font-size:0.75rem; color:#ffffff; margin-bottom:8px;"><strong>Summary:</strong> ${pkt.info || 'Genuine frame'}</p>
    `;

    // Rule 4: Never use fake hex payload fallback
    dom.deepInspectorHex.textContent = pkt.raw_hex || 'Hex wire dump unavailable for this frame.';
    dom.deepPacketInspectorPanel.style.display = 'block';
  }

  // Cached Phase 9C benchmark sample windows
  let temporalSamplesCache = [];

  async function fetchTemporalSampleWindows() {
    if (temporalSamplesCache.length > 0) return;
    try {
      const res = await fetch('/api/forecast/temporal-experimental/sample-windows');
      if (!res.ok) return;
      const data = await res.json();
      temporalSamplesCache = data.samples || [];

      if (!dom.temporalSampleSelect) return;
      dom.temporalSampleSelect.innerHTML = '';
      temporalSamplesCache.forEach((s, idx) => {
        const opt = document.createElement('option');
        opt.value = idx;
        opt.textContent = `${s.name} [Target=${s.ground_truth_target}]`;
        dom.temporalSampleSelect.appendChild(opt);
      });

      if (temporalSamplesCache.length > 0) {
        updateTemporalSampleNotes(0);
      }
    } catch (err) {
      console.warn('Error fetching temporal sample windows:', err);
    }
  }

  function updateTemporalSampleNotes(idx) {
    const sample = temporalSamplesCache[idx];
    if (!sample || !dom.temporalSampleNotesBox) return;
    dom.temporalSampleNotesBox.innerHTML = `
      <strong>Sample:</strong> ${sample.name}<br>
      <strong>Anchor Epoch:</strong> <code>${sample.anchor_epoch}</code> | <strong>Ground-Truth Target A:</strong> <code>${sample.ground_truth_target === 1 ? 'POSITIVE ONSET' : 'NEGATIVE / CLEAN'}</code><br>
      <strong>Forecast Horizon:</strong> <code>${sample.horizon_start}</code> to <code>${sample.horizon_end}</code> (5 minutes ahead)<br>
      <strong>Context:</strong> ${sample.notes}
    `;
  }

  // =========================================================================
  // 8. INTERACTIVE EVENT HANDLERS & WIRING
  // =========================================================================
  function initEventHandlers() {
    // Navigation Tabs Switcher
    dom.tabSocDashboard.addEventListener('click', () => {
      dom.tabSocDashboard.classList.add('active');
      dom.tabModelDeepDive.classList.remove('active');
      if (dom.tabTemporalExperimental) dom.tabTemporalExperimental.classList.remove('active');
      dom.soc3ColumnView.classList.add('active');
      dom.modelDeepDiveView.classList.remove('active');
      if (dom.temporalExperimentalView) dom.temporalExperimentalView.classList.remove('active');
      state.activeView = 'soc3ColumnView';
      setTimeout(onWindowResize, 50);
    });

    dom.tabModelDeepDive.addEventListener('click', () => {
      dom.tabModelDeepDive.classList.add('active');
      dom.tabSocDashboard.classList.remove('active');
      if (dom.tabTemporalExperimental) dom.tabTemporalExperimental.classList.remove('active');
      dom.modelDeepDiveView.classList.add('active');
      dom.soc3ColumnView.classList.remove('active');
      if (dom.temporalExperimentalView) dom.temporalExperimentalView.classList.remove('active');
      state.activeView = 'modelDeepDiveView';
      fetchLiveFeed();
    });

    if (dom.tabTemporalExperimental) {
      dom.tabTemporalExperimental.addEventListener('click', () => {
        dom.tabTemporalExperimental.classList.add('active');
        dom.tabSocDashboard.classList.remove('active');
        dom.tabModelDeepDive.classList.remove('active');
        if (dom.temporalExperimentalView) dom.temporalExperimentalView.classList.add('active');
        dom.soc3ColumnView.classList.remove('active');
        dom.modelDeepDiveView.classList.remove('active');
        state.activeView = 'temporalExperimentalView';
        fetchTemporalSampleWindows();
      });
    }

    // Phase 9C: Temporal Sample Select Change
    if (dom.temporalSampleSelect) {
      dom.temporalSampleSelect.addEventListener('change', (e) => {
        const idx = parseInt(e.target.value, 10);
        updateTemporalSampleNotes(idx);
      });
    }

    // Phase 9C: Run Temporal Forecast Click
    if (dom.btnRunTemporalForecast) {
      dom.btnRunTemporalForecast.addEventListener('click', async () => {
        const selectIdx = parseInt(dom.temporalSampleSelect.value, 10);
        const sample = temporalSamplesCache[selectIdx];
        if (!sample) {
          alert('Please select a valid benchmark sample window.');
          return;
        }

        dom.btnRunTemporalForecast.textContent = 'Evaluating Model...';
        dom.temporalOutputBadge.textContent = 'INFERENCE IN PROGRESS';
        dom.temporalOutputBadge.style.color = '#38bdf8';

        try {
          const res = await fetch('/api/forecast/temporal-experimental', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              features: sample.features,
              threshold: 0.5
            })
          });

          const data = await res.json();
          if (!res.ok) {
            dom.temporalOutputBadge.textContent = 'SCHEMA REJECTED';
            dom.temporalOutputBadge.style.color = '#ef4444';
            dom.temporalDecisionTitle.textContent = 'Schema Validation Error';
            dom.temporalDecisionDesc.textContent = data.error || 'Failed to evaluate sequence.';
            dom.temporalScoreCircle.className = 'score-badge-circle positive';
            dom.temporalScoreVal.textContent = 'ERR';
            dom.temporalOutputDetails.textContent = JSON.stringify(data, null, 2);
            return;
          }

          const prob = data.forecast_probability;
          const isPos = data.forecast_onset_positive;
          const scoreFmt = (prob * 100).toFixed(1) + '%';

          dom.temporalScoreVal.textContent = scoreFmt;
          dom.temporalScoreCircle.className = `score-badge-circle ${isPos ? 'positive' : 'negative'}`;

          dom.temporalOutputBadge.textContent = isPos ? 'FORECAST: ATTACK ONSET (+)' : 'FORECAST: CLEAN BASELINE (-)';
          dom.temporalOutputBadge.style.color = isPos ? '#f87171' : '#34d399';

          dom.temporalDecisionTitle.textContent = isPos
            ? '⚡ Attack Onset Forecasted in Horizon [t+3m, t+7m]'
            : '✓ Normal Baseline Activity Forecasted';

          dom.temporalDecisionDesc.textContent = isPos
            ? `Adversarial onset predicted with experimental score ${scoreFmt} (Threshold 0.50). Attack traffic expected 3 to 7 minutes post-anchor. Ground Truth Target: ${sample.ground_truth_target}.`
            : `Model forecasts continued normal activity with score ${scoreFmt} (Threshold 0.50). No attack onset anticipated. Ground Truth Target: ${sample.ground_truth_target}.`;

          dom.temporalOutputDetails.textContent = JSON.stringify(data, null, 2);
        } catch (err) {
          console.warn('Error evaluating temporal forecast:', err);
          dom.temporalOutputBadge.textContent = 'NETWORK ERROR';
        } finally {
          dom.btnRunTemporalForecast.innerHTML = `
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polygon points="5 3 19 12 5 21 5 3"></polygon>
            </svg> Evaluate Target A Forecast
          `;
        }
      });
    }

    // Phase 9C: Test Packet Rejection Click
    if (dom.btnTestPacketRejection) {
      dom.btnTestPacketRejection.addEventListener('click', async () => {
        dom.temporalOutputBadge.textContent = 'TESTING REJECTION';
        dom.temporalOutputBadge.style.color = '#fbbf24';

        try {
          const res = await fetch('/api/forecast/temporal-experimental', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              features: [{
                mean_frame_length: 512.0,
                std_frame_length: 120.0,
                tcp_packet_ratio: 0.85,
                udp_packet_ratio: 0.15
              }],
              threshold: 0.5
            })
          });

          const data = await res.json();
          dom.temporalOutputBadge.textContent = 'CROSS-LAYER REJECTION (HTTP 422)';
          dom.temporalOutputBadge.style.color = '#fbbf24';
          dom.temporalScoreCircle.className = 'score-badge-circle';
          dom.temporalScoreVal.textContent = 'BLOCKED';
          dom.temporalDecisionTitle.textContent = 'Packet-Layer Features Strictly Rejected';
          dom.temporalDecisionDesc.textContent = data.error || 'Cross-layer feature mapping rejected.';
          dom.temporalOutputDetails.textContent = JSON.stringify({
            http_status: res.status,
            rejection_policy: 'PHASE_9C_GATING',
            server_response: data
          }, null, 2);
        } catch (err) {
          console.warn('Error testing packet rejection:', err);
        }
      });
    }

    // 3D Canvas Controls
    dom.btnResetCamera.addEventListener('click', () => {
      if (controls && camera) {
        controls.target.set(0, 0, 0);
        camera.position.set(0, 160, 420);
      }
    });

    dom.btnAutoRotate.addEventListener('click', () => {
      state.autoRotate3D = !state.autoRotate3D;
      dom.btnAutoRotate.textContent = `Auto-Rotate: ${state.autoRotate3D ? 'ON' : 'OFF'}`;
      dom.btnAutoRotate.classList.toggle('alert-btn', state.autoRotate3D);
    });

    dom.btnFocusAlertNode.addEventListener('click', () => {
      focusIpIn3D(state.activeAlertIp);
    });

    dom.btnToggleFullscreen.addEventListener('click', () => {
      if (!document.fullscreenElement) {
        dom.threejsViewportContainer.requestFullscreen().catch(err => alert(err.message));
      } else {
        document.exitFullscreen();
      }
    });

    // Threat Filter Chips on 3D View
    document.querySelectorAll('.view-chip').forEach(btn => {
      btn.addEventListener('click', () => {
        applyThreatCategoryFilter(btn.dataset.filter);
      });
    });

    // Close Floating Node Inspector
    dom.btnCloseNodeInspector.addEventListener('click', () => {
      dom.threeNodeInspector.style.display = 'none';
      state.selectedNodeId = null;
    });

    // Copy IP button
    dom.insCopyIpBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(dom.insNodeIp.textContent).then(() => {
        dom.insCopyIpBtn.style.color = '#10b981';
        setTimeout(() => dom.insCopyIpBtn.style.color = '', 1200);
      });
    });

    // Close Details Drawer
    dom.btnCloseDetailsDrawer.addEventListener('click', () => {
      dom.eventDetailsDrawer.style.display = 'none';
      state.selectedLogId = null;
    });

    // Search and Log Filters
    dom.logSearchInput.addEventListener('input', (e) => {
      state.searchTerm = e.target.value.trim();
      fetchSocThreatLogs();
    });

    dom.filterSeveritySelect.addEventListener('change', (e) => {
      state.filterSeverity = e.target.value;
      fetchSocThreatLogs();
    });

    dom.filterStatusSelect.addEventListener('change', (e) => {
      state.filterStatus = e.target.value;
      fetchSocThreatLogs();
    });

    dom.btnRefreshLogs.addEventListener('click', () => {
      fetchSocThreatLogs();
    });

    document.querySelectorAll('.sev-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        const sev = chip.dataset.sev;
        dom.filterSeveritySelect.value = sev;
        state.filterSeverity = sev;
        fetchSocThreatLogs();
      });
    });

    // Real OS Ping Probe
    dom.headerPingBtn.addEventListener('click', () => {
      executePing(dom.headerPingInput.value);
    });
    dom.headerPingInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') executePing(dom.headerPingInput.value);
    });

    dom.socSendPingBtn.addEventListener('click', () => {
      executePing(dom.socPingTargetInput.value);
    });
    dom.socPingTargetInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') executePing(dom.socPingTargetInput.value);
    });

    document.querySelectorAll('.quick-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        const target = chip.dataset.target;
        dom.socPingTargetInput.value = target;
        executePing(target);
      });
    });

    // Mode Selector in Health Banner (Section 3)
    if (dom.systemModeSelect) {
      dom.systemModeSelect.addEventListener('change', async (e) => {
        const selectedMode = e.target.value;
        if (selectedMode === 'pcap') {
          // Trigger file picker or load sample
          dom.socPcapFileInput.click();
        } else {
          await switchOperatingMode(selectedMode);
        }
      });
    }

    // Interface Selector in Health Banner (Section 2)
    if (dom.systemInterfaceSelect) {
      dom.systemInterfaceSelect.addEventListener('change', async (e) => {
        const newIfaceId = e.target.value;
        const prevIfaceId = state.selectedInterfaceId;
        try {
          const res = await fetch('/api/capture/interface/select', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interface_id: newIfaceId })
          });
          if (!res.ok) {
            const errJson = await res.json().catch(() => ({}));
            const detail = errJson.detail || 'Interface selection rejected by server.';
            alert(`Interface selection rejected: ${detail}`);
            dom.systemInterfaceSelect.value = prevIfaceId || '';
            return;
          }
          state.selectedInterfaceId = newIfaceId;
          await fetchCaptureHealth();
          await fetchSocOverview();
          await fetchSocTopology();
        } catch (err) {
          console.warn('Error applying interface:', err);
          alert(`Failed to set interface: ${err.message}`);
          dom.systemInterfaceSelect.value = prevIfaceId || '';
        }
      });
    }

    // Toggle Capture Button
    dom.socToggleCaptureBtn.addEventListener('click', async () => {
      const nextCapturing = !state.isCapturing;
      const endpoint = nextCapturing ? '/api/capture/start' : '/api/capture/stop';
      const body = nextCapturing ? JSON.stringify({ mode: state.currentMode, interface_id: state.selectedInterfaceId }) : null;

      try {
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: body ? { 'Content-Type': 'application/json' } : {},
          body: body
        });
        if (res.ok) {
          state.isCapturing = nextCapturing;
          dom.socCaptureBtnLabel.textContent = nextCapturing ? 'Live Capture Active' : 'Capture Paused';
          dom.socToggleCaptureBtn.classList.toggle('success', nextCapturing);
          dom.socToggleCaptureBtn.classList.toggle('outline', !nextCapturing);
          fetchCaptureHealth();
        }
      } catch (err) {
        console.warn('Error toggling capture:', err);
      }
    });

    // Clear Buffer Button
    dom.socClearBufferBtn.addEventListener('click', async () => {
      await fetch('/api/capture/clear', { method: 'POST' });
      fetchSocOverview();
      fetchSocTopology();
      fetchCaptureHealth();
    });

    // Load Sample PCAP
    dom.socLoadSamplePcapBtn.addEventListener('click', async () => {
      dom.socLoadSamplePcapBtn.textContent = 'Dissecting PCAP...';
      try {
        const res = await fetch('/api/capture/load-sample-pcap', { method: 'POST' });
        if (res.ok) {
          state.currentMode = 'pcap';
          if (dom.systemModeSelect) dom.systemModeSelect.value = 'pcap';
          fetchCaptureHealth();
          fetchSocOverview();
          fetchSocTopology();
          fetchLiveFeed();
        }
      } finally {
        dom.socLoadSamplePcapBtn.textContent = 'Load Sample Attack PCAP (37 pkts)';
      }
    });

    // Custom PCAP Upload
    dom.socPcapFileInput.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) {
        dom.systemModeSelect.value = state.currentMode;
        return;
      }
      const formData = new FormData();
      formData.append('file', file);

      try {
        const res = await fetch('/api/capture/upload-pcap', {
          method: 'POST',
          body: formData
        });
        if (res.ok) {
          state.currentMode = 'pcap';
          if (dom.systemModeSelect) dom.systemModeSelect.value = 'pcap';
          fetchCaptureHealth();
          fetchSocOverview();
          fetchSocTopology();
          fetchLiveFeed();
        } else {
          alert('Failed to upload PCAP file.');
          dom.systemModeSelect.value = state.currentMode;
        }
      } catch (err) {
        console.warn('Error uploading PCAP:', err);
        dom.systemModeSelect.value = state.currentMode;
      }
    });

    // Advance Stream Button
    dom.btnAdvanceStream.addEventListener('click', async () => {
      try {
        const res = await fetch('/api/stream');
        if (res.ok) {
          fetchSocOverview();
          fetchSocThreatLogs();
          fetchLiveFeed();
        }
      } catch (err) {
        console.warn('Error advancing stream:', err);
      }
    });

    // Export to Excel
    dom.btnExportExcel.addEventListener('click', () => {
      window.location.href = '/api/export-xlsx';
    });

    // SHAP Tab Switcher in Deep Dive
    dom.btnShapRanking.addEventListener('click', () => {
      dom.btnShapRanking.classList.add('active');
      dom.btnShapForce.classList.remove('active');
      dom.shapRankingView.style.display = 'block';
      dom.shapForceView.style.display = 'none';
    });

    dom.btnShapForce.addEventListener('click', () => {
      dom.btnShapForce.classList.add('active');
      dom.btnShapRanking.classList.remove('active');
      dom.shapForceView.style.display = 'block';
      dom.shapRankingView.style.display = 'none';
    });

    dom.deepCloseInspectorBtn.addEventListener('click', () => {
      dom.deepPacketInspectorPanel.style.display = 'none';
    });
  }

  // Execute Real OS Ping Injection
  async function executePing(target) {
    if (!target) return;
    const cleanTarget = target.trim();

    const origText = dom.socSendPingBtn.textContent;
    dom.socSendPingBtn.textContent = 'Pinging...';
    dom.headerPingBtn.textContent = '...';

    try {
      const res = await fetch(`/api/capture/inject-ping?target=${encodeURIComponent(cleanTarget)}&count=4`);
      if (res.ok) {
        fetchSocOverview();
        fetchSocTopology();
        fetchSocThreatLogs();
        fetchCaptureHealth();
        fetchLiveFeed();
      }
    } catch (err) {
      console.warn('Error sending ping:', err);
    } finally {
      dom.socSendPingBtn.textContent = origText;
      dom.headerPingBtn.textContent = 'Ping';
    }
  }

  // =========================================================================
  // 9. INITIALIZATION & RECURRING POLLING
  // =========================================================================
  document.addEventListener('DOMContentLoaded', () => {
    initThreeJs();
    initEventHandlers();

    // Initial Data Fetch
    fetchCaptureHealth();
    fetchInterfaces();
    fetchSocOverview();
    fetchSocTopology();
    fetchSocThreatLogs();
    fetchLiveFeed();

    // Recurring polling
    setInterval(fetchCaptureHealth, 2500);
    setInterval(fetchSocOverview, 2500);
    setInterval(fetchSocTopology, 4000);
    setInterval(fetchSocThreatLogs, 5000);

    // Deep-dive feed polling when active
    setInterval(() => {
      if (state.activeView === 'modelDeepDiveView') {
        fetchLiveFeed();
      }
    }, 2500);
  });

})();
