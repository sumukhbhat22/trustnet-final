import { useEffect, useMemo, useRef } from 'react';
import * as THREE from 'three';
import { useSecurity } from '@/store/securityStore';
import type { NetworkNode, NetworkEdge } from '@/data/mockData';
import { layoutNodes, MIN_NODE_GAP } from '@/lib/graphLayout';
import { NODE_TOKENS, truncateLabel } from '@/lib/graphTheme';
import { NetworkGraphLegend } from './NetworkGraphLegend';

interface NetworkGraph3DProps {
  width?: number;
  height?: number;
  graphNodes?: NetworkNode[];
  graphEdges?: NetworkEdge[];
  onUnavailable?: () => void;
}

const FOV = 42;
const NODE_RADIUS = 0.42;

/** Resolve a theme token ("34 90% 60%") from CSS variables into a three.js colour. */
function tokenColor(token: string): THREE.Color {
  const raw = getComputedStyle(document.documentElement).getPropertyValue(`--${token}`).trim();
  const [h, s, l] = raw.split(/\s+/).map((part) => parseFloat(part));
  if ([h, s, l].some((value) => Number.isNaN(value))) return new THREE.Color(0xffffff);
  return new THREE.Color().setHSL(h / 360, s / 100, l / 100);
}

export default function NetworkGraph3D({ width = 800, height = 0, graphNodes, graphEdges, onUnavailable }: NetworkGraph3DProps) {
  const { nodes: contextNodes, edges: contextEdges, isAttackSimulated } = useSecurity();
  const nodes = graphNodes ?? contextNodes;
  const edges = graphEdges ?? contextEdges;
  const hostRef = useRef<HTMLDivElement>(null);
  const attackRef = useRef(isAttackSimulated);
  attackRef.current = isAttackSimulated;
  const unavailableRef = useRef(onUnavailable);
  unavailableRef.current = onUnavailable;
  const revealedRef = useRef<Set<string>>(new Set());
  const viewRef = useRef({ yaw: 0, pitch: 0 });

  const layout = useMemo(() => layoutNodes(nodes, width, MIN_NODE_GAP, 0), [nodes, width]);
  const canvasHeight = Math.max(340, height);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return undefined;

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'high-performance' });
    } catch {
      unavailableRef.current?.();
      return undefined;
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setClearColor(0x000000, 0);
    const canvas = renderer.domElement;
    canvas.className = 'ng3d-canvas';
    host.appendChild(canvas);
    const labelLayer = document.createElement('div');
    labelLayer.className = 'ng3d-labels';
    host.appendChild(labelLayer);

    const reduceMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
    const colors = {
      primary: tokenColor('primary'),
      foreground: tokenColor('foreground'),
      steel: tokenColor('threat-low'),
      ember: tokenColor('threat-high'),
      critical: tokenColor('threat-critical'),
    };

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(FOV, 1, 0.1, 200);
    const world = new THREE.Group();
    scene.add(world);
    scene.add(new THREE.AmbientLight(colors.foreground, 0.7));
    const key = new THREE.DirectionalLight(colors.foreground, 1.8);
    key.position.set(6, 9, 12);
    scene.add(key);
    const rim = new THREE.PointLight(colors.primary, 220, 70);
    rim.position.set(-9, 4, -7);
    scene.add(rim);

    // Columns come from the shared layout; depth is spread deterministically so nodes sit in a volume.
    const positions = new Map<string, THREE.Vector3>();
    layout.nodes.forEach((node, index) => {
      const x = ((node.x - width / 2) / (width / 2)) * 8;
      const y = ((layout.height / 2 - node.y) / MIN_NODE_GAP) * 1.25;
      const z = Math.sin(index * 2.399) * 1.6 + (node.propagationRisk / 100 - 0.5) * 1.2;
      positions.set(node.id, new THREE.Vector3(x, y, z));
    });
    let halfW = 1;
    let halfH = 1;
    let halfD = 1;
    positions.forEach((p) => {
      halfW = Math.max(halfW, Math.abs(p.x) + 1.2);
      halfH = Math.max(halfH, Math.abs(p.y) + 1.4);
      halfD = Math.max(halfD, Math.abs(p.z) + 1);
    });

    const floor = new THREE.GridHelper(halfW * 2.6, 26, colors.primary, colors.primary);
    floor.position.y = -halfH - 0.4;
    const floorMaterials = Array.isArray(floor.material) ? floor.material : [floor.material];
    floorMaterials.forEach((material) => { material.transparent = true; material.opacity = 0.12; });
    world.add(floor);

    const dustCount = 140;
    const dustPositions = new Float32Array(dustCount * 3);
    for (let i = 0; i < dustCount; i += 1) {
      dustPositions[i * 3] = Math.sin(i * 12.9898) * halfW * 1.6;
      dustPositions[i * 3 + 1] = Math.sin(i * 78.233) * halfH * 1.4;
      dustPositions[i * 3 + 2] = Math.sin(i * 37.719) * (halfD + 3);
    }
    const dustGeometry = new THREE.BufferGeometry();
    dustGeometry.setAttribute('position', new THREE.BufferAttribute(dustPositions, 3));
    world.add(new THREE.Points(dustGeometry, new THREE.PointsMaterial({ color: colors.foreground, size: 0.05, transparent: true, opacity: 0.45 })));

    // Edges first so nodes draw over them.
    type Flow = { curve: THREE.CubicBezierCurve3; mesh: THREE.Mesh; phase: number; attack: boolean; born: number; delay: number };
    type Reveal = { meshes: THREE.Mesh[]; key: string; born: number };
    const flows: Flow[] = [];
    const reveals: Reveal[] = [];
    const flowGeometry = new THREE.SphereGeometry(1, 10, 8);
    const TUBE_SEGMENTS = 48;
    const TUBE_RADIAL = 8;
    const attackKeys = new Set<string>();
    edges.forEach((edge, index) => {
      const a = positions.get(edge.from);
      const b = positions.get(edge.to);
      if (!a || !b) return;
      const bowX = Math.abs(a.x - b.x) < 0.01 ? a.x + 1.6 : (a.x + b.x) / 2;
      const curve = new THREE.CubicBezierCurve3(a, new THREE.Vector3(bowX, a.y, a.z), new THREE.Vector3(bowX, b.y, b.z), b);
      const born = performance.now();
      let delay = 0;
      if (edge.attackPath) {
        const key = `${edge.from}>${edge.to}`;
        attackKeys.add(key);
        const core = new THREE.Mesh(new THREE.TubeGeometry(curve, TUBE_SEGMENTS, 0.055, TUBE_RADIAL, false), new THREE.MeshBasicMaterial({ color: colors.ember }));
        const glow = new THREE.Mesh(new THREE.TubeGeometry(curve, TUBE_SEGMENTS, 0.16, TUBE_RADIAL, false), new THREE.MeshBasicMaterial({ color: colors.ember, transparent: true, opacity: 0.2, depthWrite: false, blending: THREE.AdditiveBlending }));
        world.add(core, glow);
        const fresh = !revealedRef.current.has(key);
        revealedRef.current.add(key);
        if (fresh && !reduceMotion) {
          core.geometry.setDrawRange(0, 0);
          glow.geometry.setDrawRange(0, 0);
          reveals.push({ meshes: [core, glow], key, born });
          delay = 2200;
        }
      } else {
        const geometry = new THREE.BufferGeometry().setFromPoints(curve.getPoints(48));
        const line = new THREE.Line(geometry, new THREE.LineDashedMaterial({ color: colors.steel, dashSize: 0.12, gapSize: 0.16, transparent: true, opacity: 0.5 }));
        line.computeLineDistances();
        world.add(line);
      }
      const pulses = edge.attackPath ? 3 : 1;
      for (let p = 0; p < pulses; p += 1) {
        const mesh = new THREE.Mesh(flowGeometry, new THREE.MeshBasicMaterial({ color: edge.attackPath ? colors.primary : colors.steel, transparent: true, opacity: edge.attackPath ? 1 : 0.7 }));
        mesh.scale.setScalar(edge.attackPath ? 0.1 : 0.05);
        world.add(mesh);
        flows.push({ curve, mesh, phase: ((index * 0.173) + p / pulses) % 1, attack: Boolean(edge.attackPath), born, delay });
      }
    });
    // Forget reveal history once the attack is cleared so the next run animates again.
    if (attackKeys.size === 0) revealedRef.current.clear();

    type Entry = { node: NetworkNode; mesh: THREE.Mesh; shell: THREE.Mesh | null; ring: THREE.Mesh; material: THREE.MeshStandardMaterial; label: HTMLDivElement; base: THREE.Color };
    const entries: Entry[] = [];
    const sphere = new THREE.SphereGeometry(NODE_RADIUS, 32, 24);
    layout.nodes.forEach((node) => {
      const base = node.compromised ? colors.critical : tokenColor(NODE_TOKENS[node.type] ?? 'threat-low');
      const material = new THREE.MeshStandardMaterial({ color: base, emissive: base, emissiveIntensity: 0.35, roughness: 0.32, metalness: 0.25 });
      const mesh = new THREE.Mesh(sphere, material);
      mesh.position.copy(positions.get(node.id)!);
      mesh.userData.id = node.id;
      world.add(mesh);

      let shell: THREE.Mesh | null = null;
      if (node.compromised) {
        shell = new THREE.Mesh(new THREE.SphereGeometry(NODE_RADIUS * 1.5, 24, 16), new THREE.MeshBasicMaterial({ color: colors.critical, transparent: true, opacity: 0.16, depthWrite: false, blending: THREE.AdditiveBlending }));
        mesh.add(shell);
      }
      const arc = Math.max(0.02, (node.propagationRisk / 100) * Math.PI * 2);
      const ring = new THREE.Mesh(new THREE.TorusGeometry(NODE_RADIUS * 1.5, 0.028, 8, 64, arc), new THREE.MeshBasicMaterial({ color: base, transparent: true, opacity: 0.8 }));
      mesh.add(ring);

      const label = document.createElement('div');
      label.className = `ng3d-label${node.compromised ? ' is-compromised' : ''}`;
      label.textContent = truncateLabel(node.label);
      labelLayer.appendChild(label);
      entries.push({ node, mesh, shell, ring, material, label, base });
    });

    // Interaction: drag to orbit, hover to inspect. Wheel and vertical touch stay with the page.
    let userYaw = viewRef.current.yaw;
    let userPitch = viewRef.current.pitch;
    let dragging = false;
    let lastX = 0;
    let lastY = 0;
    let hovered: Entry | null = null;
    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2();
    let pickPending = false;
    let pointerInside = false;

    const setHovered = (next: Entry | null) => {
      if (hovered === next) return;
      if (hovered) {
        hovered.label.classList.remove('is-hover');
        hovered.label.textContent = truncateLabel(hovered.node.label);
      }
      hovered = next;
      if (hovered) {
        hovered.label.classList.add('is-hover');
        hovered.label.textContent = `${hovered.node.label} · ${hovered.node.propagationRisk}% risk`;
      }
      canvas.style.cursor = hovered ? 'pointer' : dragging ? 'grabbing' : 'grab';
    };
    const pick = (clientX: number, clientY: number) => {
      const rect = canvas.getBoundingClientRect();
      pointer.set(((clientX - rect.left) / rect.width) * 2 - 1, -((clientY - rect.top) / rect.height) * 2 + 1);
      raycaster.setFromCamera(pointer, camera);
      const hit = raycaster.intersectObjects(entries.map((entry) => entry.mesh), false)[0];
      setHovered(hit ? entries.find((entry) => entry.mesh === hit.object) ?? null : null);
    };
    const onPointerDown = (event: PointerEvent) => {
      dragging = true;
      lastX = event.clientX;
      lastY = event.clientY;
      canvas.setPointerCapture(event.pointerId);
      canvas.style.cursor = 'grabbing';
    };
    const onPointerMove = (event: PointerEvent) => {
      pointerInside = true;
      if (dragging) {
        userYaw += (event.clientX - lastX) * 0.006;
        userPitch = THREE.MathUtils.clamp(userPitch + (event.clientY - lastY) * 0.004, -0.5, 0.5);
        lastX = event.clientX;
        lastY = event.clientY;
        return;
      }
      if (pickPending) return;
      pickPending = true;
      const { clientX, clientY } = event;
      requestAnimationFrame(() => { pickPending = false; if (pointerInside) pick(clientX, clientY); });
    };
    const onPointerUp = (event: PointerEvent) => {
      dragging = false;
      if (canvas.hasPointerCapture(event.pointerId)) canvas.releasePointerCapture(event.pointerId);
      canvas.style.cursor = hovered ? 'pointer' : 'grab';
    };
    const onPointerLeave = () => { pointerInside = false; setHovered(null); };
    canvas.addEventListener('pointerdown', onPointerDown);
    canvas.addEventListener('pointermove', onPointerMove);
    canvas.addEventListener('pointerup', onPointerUp);
    canvas.addEventListener('pointercancel', onPointerUp);
    canvas.addEventListener('pointerleave', onPointerLeave);

    let viewW = 1;
    let viewH = 1;
    const resize = () => {
      viewW = Math.max(1, host.clientWidth);
      viewH = Math.max(1, host.clientHeight);
      renderer.setSize(viewW, viewH, false);
      camera.aspect = viewW / viewH;
      const t = Math.tan(THREE.MathUtils.degToRad(FOV / 2));
      camera.position.set(0, 0, Math.max(halfH / t, halfW / (t * camera.aspect)) * 1.04 + halfD);
      camera.lookAt(0, 0, 0);
      camera.updateProjectionMatrix();
    };
    const observer = new ResizeObserver(resize);
    observer.observe(host);
    resize();

    const startedAt = performance.now();
    const tmp = new THREE.Vector3();
    const parentQ = new THREE.Quaternion();
    const spin = new THREE.Quaternion().setFromAxisAngle(new THREE.Vector3(0, 0, 1), Math.PI / 2);
    let frame = 0;
    let visible = true;

    const render = () => {
      frame = 0;
      const t = (performance.now() - startedAt) / 1000;
      world.rotation.y = userYaw + (reduceMotion ? 0 : Math.sin(t * 0.25) * 0.28);
      world.rotation.x = 0.12 + userPitch;
      world.updateMatrixWorld(true);
      world.getWorldQuaternion(parentQ).invert();
      const attacking = attackRef.current;

      entries.forEach((entry) => {
        const isHover = entry === hovered;
        const pulse = entry.node.compromised && !reduceMotion ? 0.5 + 0.5 * Math.sin(t * 3) : 0;
        entry.material.emissiveIntensity = isHover ? 0.8 : 0.35 + pulse * 0.45;
        entry.mesh.scale.setScalar(isHover ? 1.18 : 1);
        if (entry.shell) entry.shell.scale.setScalar(1 + pulse * 0.25);
        entry.ring.quaternion.copy(parentQ).multiply(camera.quaternion).multiply(spin);

        entry.mesh.getWorldPosition(tmp);
        tmp.y -= NODE_RADIUS * 1.9;
        tmp.project(camera);
        const x = (tmp.x * 0.5 + 0.5) * viewW;
        const y = (-tmp.y * 0.5 + 0.5) * viewH;
        entry.label.style.transform = `translate(-50%,0) translate(${x.toFixed(1)}px,${y.toFixed(1)}px)`;
        entry.label.style.opacity = isHover ? '1' : String(THREE.MathUtils.clamp(1 - (tmp.z - 0.9) * 8, 0.45, 1));
        entry.label.style.zIndex = isHover ? '3' : '1';
      });

      flows.forEach((flow, index) => {
        const speed = flow.attack ? (attacking ? 0.5 : 0.22) : 0.12 + (index % 3) * 0.03;
        const progress = reduceMotion ? 0.5 : (flow.phase + t * speed) % 1;
        flow.mesh.position.copy(flow.curve.getPointAt(progress));
        flow.mesh.visible = performance.now() - flow.born >= flow.delay;
      });

      // Grow newly infected links from source to target.
      reveals.forEach((reveal) => {
        const progress = Math.min(1, (performance.now() - reveal.born) / 2200);
        const count = Math.floor(progress * TUBE_SEGMENTS) * TUBE_RADIAL * 6;
        reveal.meshes.forEach((mesh) => mesh.geometry.setDrawRange(0, progress >= 1 ? Infinity : count));
      });

      renderer.render(scene, camera);
      if (visible) frame = requestAnimationFrame(render);
    };
    const start = () => { if (!frame) frame = requestAnimationFrame(render); };
    const visibility = new IntersectionObserver(([entry]) => {
      visible = entry.isIntersecting;
      if (visible) start();
    });
    visibility.observe(host);
    start();

    return () => {
      viewRef.current = { yaw: userYaw, pitch: userPitch };
      visible = false;
      if (frame) cancelAnimationFrame(frame);
      observer.disconnect();
      visibility.disconnect();
      canvas.removeEventListener('pointerdown', onPointerDown);
      canvas.removeEventListener('pointermove', onPointerMove);
      canvas.removeEventListener('pointerup', onPointerUp);
      canvas.removeEventListener('pointercancel', onPointerUp);
      canvas.removeEventListener('pointerleave', onPointerLeave);
      scene.traverse((object) => {
        const target = object as THREE.Mesh;
        target.geometry?.dispose?.();
        const material = target.material as THREE.Material | THREE.Material[] | undefined;
        if (Array.isArray(material)) material.forEach((m) => m.dispose());
        else material?.dispose?.();
      });
      renderer.dispose();
      canvas.remove();
      labelLayer.remove();
    };
  }, [layout, edges, width]);

  return (
    <div className="network-graph">
      <div ref={hostRef} className="ng3d" style={{ height: canvasHeight }} role="img" aria-label="3D network topology graph. Drag to rotate." />
      <NetworkGraphLegend />
    </div>
  );
}
