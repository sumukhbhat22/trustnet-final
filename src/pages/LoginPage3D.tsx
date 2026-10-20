import { useEffect, useRef, useState, type FormEvent } from "react";
import { createPortal } from "react-dom";
import { useNavigate } from "react-router-dom";
import * as THREE from "three";
import { collectFingerprint, getFingerprintId } from "@/services/fingerprintService";
import { mlBackendService } from "@/services/mlBackendService";
import { getCanvasBufferSize } from "@/lib/webglSizing";

const CHAPTERS = 5;
const MAX_TRACE_PIXELS = 8_300_000;

const blackHoleFragment = `
precision highp float;
uniform vec2 uRes;
uniform float uTime;
uniform vec2 uCenter;
uniform float uK;
uniform float uTilt;
uniform float uGain;
uniform float uInc;
uniform int uSteps;
float hash(vec2 p) { p = fract(p * vec2(123.34, 456.21)); p += dot(p, p + 45.32); return fract(p.x * p.y); }
float hash31(vec3 p) { p = fract(p * .1031); p += dot(p, p.yzx + 33.33); return fract((p.x + p.y) * p.z); }
vec3 hash33(vec3 p) { vec3 q = fract(p * vec3(.1031, .1030, .0973)); q += dot(q, q.yxz + 33.33); return fract((q.xxy + q.yxx) * q.zyx); }
float noise(vec2 p, float period) {
  vec2 i = floor(p), f = fract(p); f = f * f * (3.0 - 2.0 * f);
  float a = hash(vec2(mod(i.x, period), i.y));
  float b = hash(vec2(mod(i.x + 1.0, period), i.y));
  float c = hash(vec2(mod(i.x, period), i.y + 1.0));
  float d = hash(vec2(mod(i.x + 1.0, period), i.y + 1.0));
  return mix(mix(a, b, f.x), mix(c, d, f.x), f.y);
}
float fbm(vec2 p, float period) { float a = .5, sum = 0.0; for (int i = 0; i < 4; i++) { sum += a * noise(p, period); p *= 2.0; period *= 2.0; a *= .5; } return sum; }
vec3 ramp(float i) { return vec3(1.0, .46, .13) * i + vec3(1.0, .80, .52) * i * i * .55 + vec3(1.0, .95, .85) * i * i * i * .35; }
vec3 starfield(vec3 d) {
  vec3 q = d * 240.0, cell = floor(q), jitter = hash33(cell) - .5;
  float star = step(.972, hash31(cell)) * (1.0 - smoothstep(0.0, .16, length(fract(q) - .5 - jitter * .5))) * (.35 + 1.3 * hash31(cell + 7.0));
  vec3 tint = mix(vec3(1.0, .82, .6), vec3(.7, .82, 1.0), hash31(cell + 3.0));
  vec3 q2 = d * 90.0, c2 = floor(q2);
  float star2 = step(.985, hash31(c2 + 11.0)) * (1.0 - smoothstep(0.0, .2, length(fract(q2) - .5 - (hash33(c2 + 5.0) - .5) * .5)));
  float nebula = noise(vec2(d.x * 4.0 + d.z * 2.0, d.y * 5.0), 1000.0) * noise(vec2(d.z * 3.0, d.x * 3.0 + 4.0), 1000.0);
  return tint * star + vec3(.9, .9, 1.0) * star2 * 1.2 + vec3(.35, .24, .16) * nebula * .05;
}
void main() {
  vec2 uv = (gl_FragCoord.xy - .5 * uRes) / uRes.y - uCenter;
  float cs = cos(uTilt), sn = sin(uTilt); uv = mat2(cs, -sn, sn, cs) * uv;
  const float DIST = 30.0, R0 = 22.0;
  vec3 camPos = vec3(0.0, sin(uInc), -cos(uInc)) * DIST;
  vec3 forward = normalize(-camPos), right = normalize(cross(forward, vec3(0.0, 1.0, 0.0))), up = cross(right, forward);
  vec3 dir = normalize(forward + (right * uv.x + up * uv.y) * uK);
  float impact = length(cross(camPos, dir));
  vec3 color = vec3(0.0);
  if (impact > R0) {
    vec3 normal = normalize(-camPos + dot(camPos, dir) * dir);
    color = starfield(normalize(dir + normal * (2.0 / impact)));
  } else {
    vec3 p = camPos + dir * (-dot(camPos, dir) - sqrt(R0 * R0 - impact * impact));
    vec3 velocity = dir, acc = vec3(0.0); float opticalDepth = 1.0; bool swallowed = false;
    for (int i = 0; i < 240; i++) {
      if (i >= uSteps) break;
      float r = length(p);
      if (r < 1.02) { swallowed = true; break; }
      if (r > R0 + .5 && dot(p, velocity) > 0.0) break;
      float dt = clamp(.05 * r, .03, .45); dt = min(dt, .10 + abs(p.y) * .7);
      float density = exp(-pow(p.y / (.05 * r + .03), 2.0));
      float disk = smoothstep(3.0, 3.6, r) * (1.0 - smoothstep(5.8, 10.0, r));
      float emissivity = density * disk;
      if (emissivity > .004) {
        float angle = atan(p.z, p.x), u = angle / 6.2831853 * 24.0 + uTime * .9 * pow(r / 3.0, -1.5);
        float turbulence = fbm(vec2(u, r * 3.2), 24.0), speed = sqrt(.5 / max(r - 1.0, .6));
        vec3 tangent = normalize(vec3(p.z, 0.0, -p.x)) * speed;
        float redshift = sqrt(1.0 - speed * speed) * sqrt(max(1.0 - 1.0 / r, .05)) / (1.0 + dot(tangent, velocity));
        float energy = pow(3.0 / r, 1.9) * (.18 + 1.9 * turbulence) * pow(clamp(redshift, .3, 2.4), 2.2);
        acc += opticalDepth * ramp(energy) * emissivity * dt * 6.5;
        opticalDepth *= exp(-emissivity * dt * 1.7);
        if (opticalDepth < .01) break;
      }
      vec3 acceleration = -1.5 * impact * impact * p / pow(r, 5.0);
      velocity = normalize(velocity + acceleration * dt); p += velocity * dt;
    }
    color = acc;
    if (!swallowed && length(p) > 6.0 && dot(p, velocity) > 0.0) color += opticalDepth * starfield(velocity);
  }
  color *= uGain; color = 1.0 - exp(-color * 1.25); color = pow(color, vec3(.9));
  color += (hash(gl_FragCoord.xy + fract(uTime)) - .5) * .012;
  gl_FragColor = vec4(max(color, vec3(.010, .012, .019)), 1.0);
}`;

function smoothStep(edge0: number, edge1: number, value: number) {
  const t = Math.min(1, Math.max(0, (value - edge0) / (edge1 - edge0)));
  return t * t * (3 - 2 * t);
}

export default function LoginPage3D() {
  const navigate = useNavigate();
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const formRef = useRef<HTMLFormElement | null>(null);
  const chapterRefs = useRef<Array<HTMLElement | null>>([]);
    const [username, setUsername] = useState(import.meta.env.DEV ? "sumukh" : "");
  const [password, setPassword] = useState("");
  const [authenticating, setAuthenticating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loginStep, setLoginStep] = useState<"password" | "totp">("password");
  const [totpCode, setTotpCode] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  const syncChapterVisibility = (progress: number) => {
    chapterRefs.current.forEach((element, index) => {
      if (!element) return;
      const point = index / (CHAPTERS - 1);
      const halfRange = .5 / (CHAPTERS - 1) * 1.05;
      let opacity = 1 - smoothStep(halfRange * .45, halfRange, Math.abs(progress - point));
      if (index === 0) opacity = 1 - smoothStep(.02, .1, progress);
      if (index === CHAPTERS - 1) opacity = smoothStep(.74, .9, progress);
      element.style.opacity = opacity.toFixed(3);
      element.style.visibility = opacity < .01 ? "hidden" : "visible";
      element.style.pointerEvents = opacity > .55 ? "auto" : "none";
    });
  };

  useEffect(() => {
    const updateTextVisibility = () => {
      const maxScroll = document.documentElement.scrollHeight - window.innerHeight;
      syncChapterVisibility(maxScroll > 0 ? window.scrollY / maxScroll : 0);
    };
    updateTextVisibility();
    window.addEventListener("scroll", updateTextVisibility, { passive: true });
    return () => window.removeEventListener("scroll", updateTextVisibility);
  }, []);

  const goToChapter = (index: number) => {
    const maxScroll = document.documentElement.scrollHeight - window.innerHeight;
    syncChapterVisibility(index / (CHAPTERS - 1));
    window.scrollTo({ top: maxScroll * index / (CHAPTERS - 1), behavior: "auto" });
  };

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ canvas, antialias: false, alpha: false, powerPreference: "high-performance" });
    } catch {
      document.body.classList.add("cr-webgl-fallback");
      return () => document.body.classList.remove("cr-webgl-fallback");
    }

    let rawDpr = window.devicePixelRatio || 1;
    let dpr = Math.min(rawDpr, 2);
    let cssWidth = 0;
    let cssHeight = 0;
    renderer.setPixelRatio(dpr);
    renderer.autoClear = false;
    renderer.setClearColor(0x04050a, 1);
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(60, 1, .1, 1200);
    const rayScene = new THREE.Scene();
    const rayMaterial = new THREE.ShaderMaterial({
      depthTest: false,
      depthWrite: false,
      uniforms: {
        uRes: { value: new THREE.Vector2(1, 1) },
        uTime: { value: 0 },
        uCenter: { value: new THREE.Vector2(0, 0) },
        uK: { value: .4 },
        uTilt: { value: -.1 },
        uGain: { value: 1 },
        uInc: { value: .12 },
        uSteps: { value: 150 },
      },
      vertexShader: "void main(){gl_Position=vec4(position.xy,0.0,1.0);}",
      fragmentShader: blackHoleFragment,
    });
    const rayPlane = new THREE.Mesh(new THREE.PlaneGeometry(2, 2), rayMaterial);
    rayPlane.frustumCulled = false;
    rayScene.add(rayPlane);

    let quality = 1;
    let maxQuality = Math.min(2 / dpr, 2);
    let rayTarget: THREE.WebGLRenderTarget | null = null;
    const makeRayTarget = () => {
      rayTarget?.dispose();
      const bufferSize = getCanvasBufferSize(cssWidth, cssHeight, dpr, quality, MAX_TRACE_PIXELS);
      rayMaterial.uniforms.uSteps.value = quality >= .9 ? 230 : 150;
      rayTarget = new THREE.WebGLRenderTarget(bufferSize.width, bufferSize.height, {
        minFilter: THREE.LinearFilter,
        magFilter: THREE.LinearFilter,
        format: THREE.RGBAFormat,
        depthBuffer: false,
        stencilBuffer: false,
      });
      rayMaterial.uniforms.uRes.value.set(rayTarget.width, rayTarget.height);
    };

    const displayMaterial = new THREE.ShaderMaterial({
      depthTest: false,
      depthWrite: false,
      uniforms: { uTex: { value: null }, uAspect: { value: 1.78 }, uOutputSize: { value: new THREE.Vector2(1, 1) } },
      vertexShader: "void main(){gl_Position=vec4(position.xy,0.0,1.0);}",
      fragmentShader: `
        precision highp float;
        uniform sampler2D uTex; uniform float uAspect; uniform vec2 uOutputSize;
        void main(){
          vec2 uv=gl_FragCoord.xy/uOutputSize;
          vec3 center=texture2D(uTex,uv).rgb, halo1=vec3(0.0),halo2=vec3(0.0),glare=vec3(0.0);
          for(int i=0;i<12;i++){float a=float(i)*.5236;vec2 d=vec2(cos(a)/uAspect,sin(a));halo1+=max(texture2D(uTex,uv+d*.010).rgb-.45,0.0);halo2+=max(texture2D(uTex,uv+d*.032).rgb-.40,0.0);}
          for(int j=-6;j<=6;j++){glare+=max(texture2D(uTex,uv+vec2(float(j)*.014,0.0)).rgb-.50,0.0)*(1.0-abs(float(j))/7.0);}
          gl_FragColor=vec4(center+halo1/12.0*.7+halo2/12.0*.9+glare/6.0*.28,1.0);
        }`,
    });
    const displayScene = new THREE.Scene();
    const displayCamera = new THREE.OrthographicCamera(-1, 1, 1, -1, 0, 2);
    displayCamera.position.z = 1;
    const displayPlane = new THREE.Mesh(new THREE.PlaneGeometry(2, 2), displayMaterial);
    displayPlane.frustumCulled = false;
    displayScene.add(displayPlane);

    const starCount = 2600;
    const starPositions = new Float32Array(starCount * 3);
    for (let i = 0; i < starCount; i++) {
      starPositions[i * 3] = (Math.random() - .5) * 150;
      starPositions[i * 3 + 1] = (Math.random() - .5) * 110;
      starPositions[i * 3 + 2] = -Math.random() * 340 + 30;
    }
    const starGeometry = new THREE.BufferGeometry();
    starGeometry.setAttribute("position", new THREE.BufferAttribute(starPositions, 3));
    const starMaterial = new THREE.PointsMaterial({ color: 0xffddb5, size: .22, transparent: true, opacity: .8, sizeAttenuation: true, depthWrite: false });
    const stars = new THREE.Points(starGeometry, starMaterial);
    stars.frustumCulled = false;
    scene.add(stars);

    const ringGroup = new THREE.Group();
    const steelLine = new THREE.LineBasicMaterial({ color: 0xcfdbe3, transparent: true, opacity: .78 });
    const amberLine = new THREE.LineBasicMaterial({ color: 0xf5a33b, transparent: true, opacity: .9 });
    const moduleEdges = new THREE.EdgesGeometry(new THREE.BoxGeometry(2.6, 1.1, 1.8));
    for (let i = 0; i < 12; i++) {
      const angle = i / 12 * Math.PI * 2;
      const module = new THREE.LineSegments(moduleEdges, steelLine);
      module.position.set(Math.cos(angle) * 7, Math.sin(angle) * 7, 0);
      module.rotation.z = angle + Math.PI / 2;
      ringGroup.add(module);
    }
    const stationRing = Array.from({ length: 97 }, (_, i) => {
      const angle = i / 96 * Math.PI * 2;
      return new THREE.Vector3(Math.cos(angle) * 5.8, Math.sin(angle) * 5.8, 0);
    });
    ringGroup.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(stationRing), steelLine));
    ringGroup.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(stationRing.map((point) => point.clone().multiplyScalar(8.1 / 5.8))), steelLine));
    const hub = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.CylinderGeometry(1.1, 1.1, 3.2, 10)), amberLine);
    hub.rotation.x = Math.PI / 2;
    ringGroup.add(hub);
    ringGroup.position.set(11, -1.5, -82);
    ringGroup.rotation.set(1.05, .35, 0);
    scene.add(ringGroup);

    const network = new THREE.Group();
    network.position.set(-11, .5, -150);
    scene.add(network);
    const nodePoints = Array.from({ length: 22 }, () => {
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      const radius = 3 + Math.random() * 6.5;
      return new THREE.Vector3(radius * Math.sin(phi) * Math.cos(theta), radius * Math.sin(phi) * Math.sin(theta) * .8, radius * Math.cos(phi));
    });
    const nodeGeometry = new THREE.BufferGeometry().setFromPoints(nodePoints);
    const nodeMaterial = new THREE.PointsMaterial({ color: 0xf5a33b, size: .65, transparent: true, opacity: .9, depthWrite: false });
    network.add(new THREE.Points(nodeGeometry, nodeMaterial));
    const edgePoints: THREE.Vector3[] = [];
    for (let i = 0; i < nodePoints.length; i++) {
      for (let j = i + 1; j < nodePoints.length; j++) {
        if (nodePoints[i].distanceTo(nodePoints[j]) < 5.4) edgePoints.push(nodePoints[i], nodePoints[j]);
      }
    }
    network.add(new THREE.LineSegments(new THREE.BufferGeometry().setFromPoints(edgePoints), new THREE.LineBasicMaterial({ color: 0x7ea3b8, transparent: true, opacity: .44, depthWrite: false })));

    const agents = new THREE.Group();
    agents.position.set(10, 0, -212);
    scene.add(agents);
    const orbitPoints = Array.from({ length: 121 }, (_, i) => {
      const angle = i / 120 * Math.PI * 2;
      return new THREE.Vector3(Math.cos(angle) * 7, 0, Math.sin(angle) * 7);
    });
    const orbit = new THREE.Line(new THREE.BufferGeometry().setFromPoints(orbitPoints), new THREE.LineBasicMaterial({ color: 0x7ea3b8, transparent: true, opacity: .4 }));
    orbit.rotation.set(.5, 0, .25);
    agents.add(orbit);
    const agentGeometry = new THREE.EdgesGeometry(new THREE.OctahedronGeometry(1.1));
    const agentMeshes = Array.from({ length: 3 }, (_, i) => {
      const mesh = new THREE.LineSegments(agentGeometry, i === 1 ? amberLine : steelLine);
      agents.add(mesh);
      return mesh;
    });
    const agentCore = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.IcosahedronGeometry(1.9, 1)), amberLine);
    agents.add(agentCore);

    let progress = 0;
    let targetProgress = 0;
    let mouseX = 0;
    let mouseY = 0;
    let targetMouseX = 0;
    let targetMouseY = 0;
    let avgFrameMs = 16;
    let lastQualityChange = 0;
    let lastFrame = performance.now();
    const startedAt = lastFrame;
    let rafId = 0;
    const chapterElements = chapterRefs.current;
    let textLayouts = chapterElements.map(() => ({ x: 0, y: 0, cap: .2 }));
    const railButtons = Array.from(document.querySelectorAll<HTMLButtonElement>(".cr-rail button"));
    const depth = document.getElementById("cr-depth");
    const horizon = document.getElementById("cr-horizon");
    const clock = document.getElementById("cr-clock");
    const hint = document.getElementById("cr-hint");
    const applyChapterVisibility = (value: number) => {
      let bestOpacity = -1;
      let activeChapter = 0;
      chapterElements.forEach((element, index) => {
        if (!element) return;
        const chapterPosition = index / (CHAPTERS - 1);
        const halfRange = .5 / (CHAPTERS - 1) * 1.05;
        const distance = Math.abs(value - chapterPosition);
        let opacity = 1 - smoothStep(halfRange * .45, halfRange, distance);
        if (index === 0) opacity = 1 - smoothStep(.02, .1, value);
        if (index === CHAPTERS - 1) opacity = smoothStep(.74, .9, value);
        element.style.opacity = opacity.toFixed(3);
        const direction = value < chapterPosition ? 1 : -1;
        const offset = (1 - opacity) * 26 * direction;
        const base = element.classList.contains("center") ? "translate(-50%, -50%)" : "translateY(-50%)";
        element.style.transform = `${base} translateY(${offset.toFixed(1)}px)`;
        element.style.pointerEvents = opacity > .55 ? "auto" : "none";
        element.style.visibility = opacity < .01 ? "hidden" : "visible";
        if (opacity > bestOpacity) {
          bestOpacity = opacity;
          activeChapter = index;
        }
      });
      railButtons.forEach((button, index) => button.classList.toggle("active", index === activeChapter));
      document.documentElement.style.setProperty("--cr-left", String(Math.min(1, (value > .13 && value < .42 ? 1 : 0) + (value > .62 && value < .9 ? 1 : 0))));
      document.documentElement.style.setProperty("--cr-right", String(Math.min(1, (value > .36 && value < .65 ? 1 : 0) + (value > .82 ? 1 : 0))));
      document.documentElement.style.setProperty("--cr-center", String(value < .1 ? 1 : 0));
    };
    const updateProgress = () => {
      const scrollable = document.documentElement.scrollHeight - window.innerHeight;
      targetProgress = scrollable > 0 ? Math.max(0, Math.min(1, window.scrollY / scrollable)) : 0;
      // Keep text/login available from the first paint and on scroll even when
      // WebGL is unavailable or a GPU frame fails.
      applyChapterVisibility(targetProgress);
    };
    const onPointerMove = (event: PointerEvent) => {
      targetMouseX = event.clientX / Math.max(1, window.innerWidth) - .5;
      targetMouseY = event.clientY / Math.max(1, window.innerHeight) - .5;
    };
    const measureTextLayout = () => {
      if (cssWidth <= 0 || cssHeight <= 0) return;
      const stacked = cssWidth <= 860 || cssWidth / cssHeight < 1;
      const padding = 16;
      textLayouts = chapterElements.map((element, index) => {
        if (!element) return { x: 0, y: 0, cap: .2 };
        if (index === 0) return { x: 0, y: -.3, cap: .1 };
        const rect = element.getBoundingClientRect();
        if (stacked) {
          const freeBottom = Math.max(80, rect.top - 28);
          return { x: 0, y: (cssHeight / 2 - freeBottom / 2) / cssHeight, cap: Math.max(.025, Math.min(.12, freeBottom / cssHeight / 5)) };
        }
        const textOnRight = element.classList.contains("right") || element.classList.contains("cr-dock");
        const freeStart = textOnRight ? padding + 120 : rect.right + 28;
        const freeEnd = textOnRight ? rect.left - 28 : cssWidth - padding;
        const freeCenter = (freeStart + freeEnd) / 2;
        const freeHalfWidth = Math.max(60, (freeEnd - freeStart) / 2);
        return {
          x: (freeCenter - cssWidth / 2) / cssHeight,
          y: 0,
          cap: Math.max(.025, Math.min(.24, freeHalfWidth / cssHeight / 2.7)),
        };
      });
    };
    const resize = () => {
      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      const nextRawDpr = window.devicePixelRatio || 1;
      if (width <= 0 || height <= 0) return;
      cssWidth = width;
      cssHeight = height;
      rawDpr = nextRawDpr;
      dpr = Math.min(rawDpr, 2);
      maxQuality = Math.min(2 / dpr, 2);
      quality = Math.min(quality, maxQuality);
      renderer.setPixelRatio(dpr);
      renderer.setSize(width, height, false);
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      displayMaterial.uniforms.uAspect.value = camera.aspect;
      displayMaterial.uniforms.uOutputSize.value.copy(renderer.getDrawingBufferSize(new THREE.Vector2()));
      makeRayTarget();
      updateProgress();
      measureTextLayout();
    };
    const resizeObserver = new ResizeObserver(resize);
    resizeObserver.observe(canvas);
    chapterElements.forEach((element) => { if (element) resizeObserver.observe(element); });
    window.addEventListener("resize", resize);
    window.addEventListener("scroll", updateProgress, { passive: true });
    window.addEventListener("pointermove", onPointerMove, { passive: true });
    resize();

    const chapterLayout = (chapterProgress: number) => {
      const index = Math.min(CHAPTERS - 2, Math.max(0, Math.floor(chapterProgress)));
      const fraction = chapterProgress - index;
      const start = textLayouts[index] ?? { x: 0, y: 0, cap: .2 };
      const end = textLayouts[index + 1] ?? start;
      return {
        x: start.x + (end.x - start.x) * fraction,
        y: start.y + (end.y - start.y) * fraction,
        cap: start.cap + (end.cap - start.cap) * fraction,
      };
    };

    const animate = (now: number) => {
      rafId = window.requestAnimationFrame(animate);
      if (canvas.clientWidth !== cssWidth || canvas.clientHeight !== cssHeight || (window.devicePixelRatio || 1) !== rawDpr) {
        resize();
      }
      const dt = Math.min(50, now - lastFrame);
      lastFrame = now;
      avgFrameMs = avgFrameMs * .95 + dt * .05;
      progress += (targetProgress - progress) * (reduceMotion ? 1 : Math.min(1, dt / 200));
      mouseX += (targetMouseX - mouseX) * Math.min(1, dt / 300);
      mouseY += (targetMouseY - mouseY) * Math.min(1, dt / 300);
      const time = (now - startedAt) / 1000 * (reduceMotion ? .25 : 1);
      const chapterProgress = progress * (CHAPTERS - 1);
      const activeChapter = Math.min(CHAPTERS - 1, Math.round(chapterProgress));
      railButtons.forEach((button, index) => button.classList.toggle("active", index === activeChapter));
      const position = chapterLayout(chapterProgress);
      const grow = smoothStep(0, .8, progress);
      const radius = Math.min(.085 + .115 * grow, position.cap);
      rayMaterial.uniforms.uCenter.value.set(position.x + mouseX * .006, position.y - mouseY * .005);
      rayMaterial.uniforms.uK.value = .0867 / (radius * (1 + .012 * Math.sin(time * .7)));
      rayMaterial.uniforms.uInc.value = .14 - .08 * grow + mouseY * .025;
      rayMaterial.uniforms.uTilt.value = -.09 + mouseX * .05;
      rayMaterial.uniforms.uGain.value = .58 + .10 * grow;
      rayMaterial.uniforms.uTime.value = time;

      const cameraZ = -progress * 268;
      camera.position.set(mouseX * (reduceMotion ? 0 : 3.2), -mouseY * (reduceMotion ? 0 : 2.2), cameraZ);
      camera.rotation.y = -mouseX * .06;
      camera.rotation.x = -mouseY * .04;
      stars.rotation.z = mouseX * .02;
      ringGroup.visible = Math.abs(cameraZ + 82) < 78;
      network.visible = Math.abs(cameraZ + 150) < 85;
      agents.visible = Math.abs(cameraZ + 212) < 62 && activeChapter !== 2;
      ringGroup.rotation.z = time * .16;
      agentMeshes.forEach((mesh, index) => {
        const angle = time * .5 + index * Math.PI * 2 / 3;
        mesh.position.set(Math.cos(angle) * 7, 0, Math.sin(angle) * 7).applyEuler(orbit.rotation);
        mesh.rotation.set(time * .5, time * (.8 + index * .3), 0);
      });
      agentCore.rotation.set(time * .2, -time * .3, 0);
      network.rotation.y = time * .08;

      renderer.setRenderTarget(rayTarget);
      renderer.clear(true, true, true);
      renderer.render(rayScene, camera);
      renderer.setRenderTarget(null);
      displayMaterial.uniforms.uTex.value = rayTarget.texture;
      if (now - lastQualityChange > 2500) {
        if (avgFrameMs > 34 && quality > .5) {
          quality = Math.max(.5, quality * .85);
          lastQualityChange = now;
          makeRayTarget();
          avgFrameMs = 20;
        } else if (avgFrameMs < 18.5 && quality < maxQuality - .01) {
          quality = Math.min(maxQuality, quality * 1.25);
          lastQualityChange = now;
          makeRayTarget();
          avgFrameMs = 20;
        }
      }
      renderer.clear(true, true, true);
      renderer.render(displayScene, displayCamera);
      renderer.clearDepth();
      renderer.render(scene, camera);

      let bestOpacity = -1;
      chapterElements.forEach((element, index) => {
        if (!element) return;
        const chapterPosition = index / (CHAPTERS - 1);
        const halfRange = .5 / (CHAPTERS - 1) * 1.05;
        const distance = Math.abs(progress - chapterPosition);
        let opacity = 1 - smoothStep(halfRange * .45, halfRange, distance);
        if (index === 0) opacity = 1 - smoothStep(.02, .1, progress);
        if (index === CHAPTERS - 1) opacity = smoothStep(.74, .9, progress);
        element.style.opacity = opacity.toFixed(3);
        const direction = progress < chapterPosition ? 1 : -1;
        const offset = (1 - opacity) * 26 * direction;
        const base = element.classList.contains("center") ? "translate(-50%, -50%)" : "translateY(-50%)";
        element.style.transform = `${base} translateY(${offset.toFixed(1)}px)`;
        element.style.pointerEvents = opacity > .55 ? "auto" : "none";
        element.style.visibility = opacity < .01 ? "hidden" : "visible";
        if (opacity > bestOpacity) bestOpacity = opacity;
      });
      if (depth) depth.textContent = `${(progress * 4.2).toFixed(2)} AU`;
      if (horizon) horizon.textContent = `${(18 - 16.96 * progress).toFixed(2)} RS`;
      if (clock) {
        const seconds = Math.floor(time);
        clock.textContent = `T+ ${[Math.floor(seconds / 3600), Math.floor(seconds % 3600 / 60), seconds % 60].map((value) => String(value).padStart(2, "0")).join(":")}`;
      }
      if (hint) hint.style.opacity = progress < .03 ? "1" : "0";
      document.documentElement.style.setProperty("--cr-left", String(Math.min(1, (progress > .13 && progress < .42 ? 1 : 0) + (progress > .62 && progress < .9 ? 1 : 0))));
      document.documentElement.style.setProperty("--cr-right", String(Math.min(1, (progress > .36 && progress < .65 ? 1 : 0) + (progress > .82 ? 1 : 0))));
      document.documentElement.style.setProperty("--cr-center", String(progress < .1 ? 1 : 0));
    };
    updateProgress();
    rafId = window.requestAnimationFrame(animate);

    return () => {
      window.cancelAnimationFrame(rafId);
      resizeObserver.disconnect();
      window.removeEventListener("resize", resize);
      window.removeEventListener("scroll", updateProgress);
      window.removeEventListener("pointermove", onPointerMove);
      rayTarget?.dispose();
      scene.traverse((object) => {
        if (object instanceof THREE.Mesh || object instanceof THREE.Points || object instanceof THREE.Line || object instanceof THREE.LineSegments) {
          object.geometry.dispose();
          const materials = Array.isArray(object.material) ? object.material : [object.material];
          materials.forEach((material) => material.dispose());
        }
      });
      rayScene.traverse((object) => {
        if (object instanceof THREE.Mesh) object.geometry.dispose();
      });
      rayMaterial.dispose();
      displayMaterial.dispose();
      displayPlane.geometry.dispose();
      renderer.dispose();
    };
  }, []);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setAuthenticating(true);
    try {
      if (loginStep === "totp") {
        if (!totpCode.trim()) {
          setError("Enter your authenticator code or a backup code.");
          return;
        }
        await mlBackendService.verifyTotpLogin(totpCode.trim());
        navigate("/overview");
      } else {
        if (!username.trim() || !password) {
          setError("Username and passphrase are required.");
          return;
        }
        const fingerprint = collectFingerprint();
        const result = await mlBackendService.login(username.trim(), password, fingerprint, getFingerprintId(fingerprint));
        if (result.login_status !== "allowed") {
          setError(result.message || "Access denied. This device could not be verified.");
          return;
        }

        // Enforce the optional TOTP step before entering the dashboard. The status
        // route is exempt from the pending-MFA guard so this check is safe here.
        try {
          const totp = await mlBackendService.getTotpStatus();
          if (totp.enrolled) {
            setLoginStep("totp");
            setTotpCode("");
            setError(null);
            return;
          }
        } catch (statusError) {
          await mlBackendService.logout();
          throw statusError;
        }
        navigate("/overview");
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Authentication failed. Check the backend and try again.");
    } finally {
      setAuthenticating(false);
    }
  }

  const setChapterRef = (index: number) => (element: HTMLElement | null) => { chapterRefs.current[index] = element; };

  return (
    <>
      {createPortal(<canvas id="cr-gl" className="cr-webgl-canvas" ref={canvasRef} aria-hidden="true" />, document.body)}
      <main className="cr-root">
      <style>{`
        .cr-webgl-canvas{position:fixed;inset:0;width:100%;height:100%;display:block;z-index:0;pointer-events:none;background:#04050a}body.cr-webgl-fallback .cr-webgl-canvas{display:none}body.cr-webgl-fallback{background:radial-gradient(ellipse 60% 40% at 50% 45%,#3a2410 0%,#0b0805 38%,#04050a 70%)}
        .cr-root{--void:#04050a;--ink:#f2e8d5;--dim:#948f82;--faint:#5d5a52;--amber:#f5a33b;--ember:#ff6a2b;--steel:#7ea3b8;--line:rgba(245,163,59,.28);--glass:rgba(8,9,14,.72);position:relative;z-index:1;min-height:100vh;background:transparent;color:var(--ink);font-family:'Jost','Helvetica Neue',Arial,sans-serif;font-weight:300;color-scheme:dark;overscroll-behavior-y:contain}
        .cr-root *{box-sizing:border-box}
        .cr-password-wrap{position:relative}.cr-password-wrap input{padding-right:72px}.cr-eye{position:absolute;right:0;bottom:0;height:100%;padding:0 12px;color:var(--dim);background:transparent;border:0;font:400 10px 'IBM Plex Mono',monospace;letter-spacing:.12em;text-transform:uppercase;cursor:pointer}.cr-eye:hover,.cr-eye:focus-visible{color:var(--amber);outline:none}.cr-mfa-code{letter-spacing:.4em;text-align:center}
        .cr-password-wrap{position:relative}.cr-password-wrap input{padding-right:72px}.cr-eye{position:absolute;right:0;bottom:0;height:100%;padding:0 12px;color:var(--dim);background:transparent;border:0;font:400 10px 'IBM Plex Mono',monospace;letter-spacing:.12em;text-transform:uppercase;cursor:pointer}.cr-eye:hover,.cr-eye:focus-visible{color:var(--amber);outline:none}.cr-mfa-code{letter-spacing:.4em;text-align:center}
        .cr-scrim{position:fixed;inset:0;z-index:3;pointer-events:none;background:linear-gradient(90deg,rgba(4,5,10,calc(.9*var(--cr-left,0))) 0,rgba(4,5,10,calc(.72*var(--cr-left,0))) 34%,transparent 56%),linear-gradient(270deg,rgba(4,5,10,calc(.9*var(--cr-right,0))) 0,rgba(4,5,10,calc(.72*var(--cr-right,0))) 34%,transparent 56%),radial-gradient(ellipse 55% 24% at 50% 38%,rgba(4,5,10,calc(.8*var(--cr-center,0))),transparent 100%)}
        .cr-vignette,.cr-grain{position:fixed;inset:0;pointer-events:none}.cr-vignette{z-index:2;background:radial-gradient(ellipse at 50% 50%,transparent 55%,rgba(0,0,0,.55) 100%)}.cr-grain{z-index:2;opacity:.045;mix-blend-mode:screen;background-image:repeating-linear-gradient(0deg,rgba(255,255,255,.5) 0 1px,transparent 1px 3px)}
        .cr-hud{position:fixed;z-index:5;font-family:'IBM Plex Mono',ui-monospace,monospace;font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--dim)}.cr-brand{top:22px;left:max(16px,3vw);display:flex;flex-direction:column;gap:6px}.cr-brand strong{font-family:'Jost',sans-serif;font-weight:400;font-size:13px;letter-spacing:.5em;color:var(--ink)}.cr-brand span{font-style:normal;display:flex;align-items:center;gap:8px}.cr-dot{width:6px;height:6px;border-radius:50%;background:var(--ember);box-shadow:0 0 10px var(--ember);animation:cr-pulse 2.4s ease-in-out infinite}@keyframes cr-pulse{50%{opacity:.35}}
        .cr-top-right{top:16px;right:max(16px,3vw);display:flex;align-items:center;gap:18px}.cr-button-small{font:inherit;color:var(--ink);background:rgba(4,5,10,.3);border:1px solid var(--line);padding:10px 16px;cursor:pointer;letter-spacing:.2em;transition:.25s}.cr-button-small:hover,.cr-button-small:focus-visible{border-color:var(--amber);color:var(--amber);box-shadow:0 0 24px rgba(245,163,59,.25);outline:none}.cr-rail{left:max(16px,3vw);top:50%;transform:translateY(-50%);display:flex;flex-direction:column;gap:20px}.cr-rail button{all:unset;cursor:pointer;display:flex;align-items:center;gap:12px;opacity:.45;transition:.3s}.cr-rail button:before{content:'';width:18px;height:1px;background:currentColor;transition:.3s}.cr-rail button.active{opacity:1;color:var(--amber)}.cr-rail button.active:before{width:34px}.cr-rail button:focus-visible{outline:1px solid var(--amber);outline-offset:4px}.cr-telemetry{right:max(16px,3vw);bottom:22px;text-align:right;display:flex;flex-direction:column;gap:6px;font-variant-numeric:tabular-nums}.cr-telemetry b{color:var(--ink);font-weight:500}.cr-hint{left:50%;bottom:24px;transform:translateX(-50%);display:flex;flex-direction:column;align-items:center;gap:10px;transition:opacity .5s}.cr-hint:after{content:'';width:1px;height:38px;background:linear-gradient(var(--amber),transparent);animation:cr-drop 2.2s ease-in-out infinite}@keyframes cr-drop{0%{transform:scaleY(0);transform-origin:top}50%{transform:scaleY(1);transform-origin:top}51%{transform-origin:bottom}100%{transform:scaleY(0);transform-origin:bottom}}
        .cr-chapter{position:fixed;z-index:4;top:50%;width:min(560px,calc(100vw - 32px));opacity:0;pointer-events:none;will-change:opacity,transform}.cr-chapter.left{left:max(200px,13vw)}.cr-chapter.right{right:max(16px,9vw);text-align:right}.cr-chapter.center{left:50%;top:36%;transform:translate(-50%,-50%);text-align:center;width:min(980px,calc(100vw - 32px))}.cr-kicker{font-family:'IBM Plex Mono',monospace;font-size:11px;letter-spacing:.3em;text-transform:uppercase;color:var(--amber);margin:0 0 20px}.cr-chapter h1,.cr-chapter h2{margin:0;font-weight:200;color:var(--ink);text-wrap:balance}.cr-chapter h1{white-space:nowrap;font-size:clamp(1.5rem,6vw,5rem);letter-spacing:.34em;text-transform:uppercase;line-height:1.05;padding-left:.34em;text-shadow:0 0 60px rgba(245,163,59,.18)}.cr-chapter h2{font-size:clamp(1.7rem,3.6vw,3rem);line-height:1.15;letter-spacing:.02em}.cr-lede{margin:22px 0 0;font-size:clamp(1rem,1.5vw,1.2rem);line-height:1.65;color:var(--dim);max-width:46ch}.cr-chapter.right .cr-lede{margin-left:auto}.cr-chapter.center .cr-lede{margin-left:auto;margin-right:auto}.cr-tags{margin-top:26px;display:flex;flex-wrap:wrap;gap:10px 22px;font-family:'IBM Plex Mono',monospace;font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--steel)}.cr-chapter.right .cr-tags{justify-content:flex-end}.cr-tags span:before{content:'+ ';color:var(--amber)}
        .cr-dock{right:max(16px,8vw);left:auto;width:min(440px,calc(100vw - 32px))}.cr-panel{position:relative;background:var(--glass);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border:1px solid var(--line);padding:34px 32px 26px;box-shadow:0 22px 80px rgba(0,0,0,.32)}.cr-panel:before,.cr-panel:after{content:'';position:absolute;width:16px;height:16px;border:1px solid var(--amber)}.cr-panel:before{top:-1px;left:-1px;border-right:0;border-bottom:0}.cr-panel:after{bottom:-1px;right:-1px;border-left:0;border-top:0}.cr-panel h2{font-size:clamp(1.5rem,2.4vw,2rem);margin-bottom:8px}.cr-panel .cr-sub{margin:0 0 26px;color:var(--dim);font-size:.95rem;line-height:1.55}.cr-field{margin-bottom:20px}.cr-field label{display:block;font-family:'IBM Plex Mono',monospace;font-size:11px;letter-spacing:.24em;text-transform:uppercase;color:var(--dim);margin:0 0 8px}.cr-field input{width:100%;font:400 16px 'IBM Plex Mono',monospace;color:var(--ink);background:rgba(255,255,255,.03);border:0;border-bottom:1px solid rgba(242,232,213,.28);padding:13px 12px;border-radius:0;transition:.25s}.cr-field input::placeholder{color:var(--faint)}.cr-field input:focus{outline:none;border-bottom-color:var(--amber);background:rgba(245,163,59,.06);box-shadow:0 10px 30px -16px rgba(245,163,59,.5)}.cr-submit{width:100%;margin-top:6px;font:500 13px 'Jost',sans-serif;letter-spacing:.3em;text-transform:uppercase;color:#1a0f02;background:var(--amber);border:0;padding:16px;cursor:pointer;transition:.25s}.cr-submit:hover,.cr-submit:focus-visible{background:#ffbb61;box-shadow:0 0 40px rgba(245,163,59,.45);outline:none}.cr-submit:disabled{opacity:.6;cursor:wait}.cr-preview{width:100%;margin-top:12px;font:400 11px 'IBM Plex Mono',monospace;letter-spacing:.18em;text-transform:uppercase;color:var(--dim);background:transparent;border:1px solid rgba(242,232,213,.16);padding:13px;cursor:pointer}.cr-preview:hover,.cr-preview:focus-visible{color:var(--ink);border-color:var(--steel);outline:none}.cr-status{min-height:1.4em;margin:16px 0 0;font:400 11px 'IBM Plex Mono',monospace;letter-spacing:.1em;color:var(--steel);text-transform:uppercase}.cr-status.error{color:var(--err)}.cr-fine{margin:18px 0 0;padding-top:16px;border-top:1px solid rgba(242,232,213,.1);font:400 10px/1.7 'IBM Plex Mono',monospace;letter-spacing:.08em;color:var(--faint);text-transform:uppercase}.cr-spacer{height:560vh;position:relative;z-index:1;pointer-events:none}
        @media(max-width:1100px){.cr-chapter.left{left:16px;width:min(520px,calc(100vw - 32px))}.cr-rail{display:none}}@media(max-width:860px){.cr-rail,.cr-telemetry,#cr-clock{display:none}.cr-chapter{top:64%}.cr-chapter.center{top:40%}.cr-scrim{background:linear-gradient(0deg,rgba(4,5,10,calc(.92*(var(--cr-left,0) + var(--cr-right,0) + var(--cr-center,0)))) 0,rgba(4,5,10,calc(.8*(var(--cr-left,0) + var(--cr-right,0) + var(--cr-center,0)))) 40%,transparent 66%)}.cr-chapter.left,.cr-chapter.right{left:16px;right:16px;width:auto;text-align:left}.cr-chapter.right .cr-lede{margin-left:0}.cr-chapter.right .cr-tags{justify-content:flex-start}.cr-chapter.dock{left:16px;right:16px;width:auto;top:66%}.cr-panel{padding:26px 22px 20px}.cr-top-right .cr-button-small{padding:9px 12px}}@media(max-width:420px){.cr-panel{padding:23px 18px 18px}.cr-top-right{top:12px}.cr-brand{top:16px}.cr-kicker{font-size:9px}.cr-panel .cr-sub{margin-bottom:18px}}@media(prefers-reduced-motion:reduce){.cr-dot,.cr-hint:after{animation:none}}
      `}</style>

      <div className="cr-scrim" aria-hidden="true" />
      <div className="cr-vignette" aria-hidden="true" />
      <div className="cr-grain" aria-hidden="true" />
      <header className="cr-hud cr-brand"><strong>TRUSTNET AI</strong><span><i className="cr-dot" />Agentic SOC · Node-07</span></header>
      <div className="cr-hud cr-top-right"><span id="cr-clock">T+ 00:00:00</span><button className="cr-button-small" type="button" onClick={() => goToChapter(4)}>Sign in ↓</button></div>
      <nav className="cr-hud cr-rail" aria-label="Login page chapters">{["Entry", "Signal", "Gravity", "Judgement", "Docking"].map((label, index) => <button key={label} type="button" onClick={() => goToChapter(index)}>{label}</button>)}</nav>
      <div className="cr-hud cr-telemetry"><span>Depth <b id="cr-depth">0.00 AU</b></span><span>Horizon <b id="cr-horizon">18.00 RS</b></span><span>Signal <b>Stable</b></span></div>
      <div className="cr-hud cr-hint" id="cr-hint">Scroll to descend</div>

      <section className="cr-chapter center" ref={setChapterRef(0)} style={{ opacity: 1, visibility: "visible" }}>
        <p className="cr-kicker">Entry point · Descending</p><h1>TrustNet AI</h1>
        <p className="cr-lede">Behavioural security for the dark between systems. Every network is a universe, and most of it is unwatched.</p>
      </section>
      <section className="cr-chapter left" ref={setChapterRef(1)}>
        <p className="cr-kicker">01 · Signal</p><h2>Every login leaves a trace in the dark.</h2>
        <p className="cr-lede">Context-Sensitive Fingerprinting learns how each person really behaves: hours, devices, places, pace. A stolen password cannot copy that.</p>
        <div className="cr-tags"><span>Isolation Forest</span><span>Device trust</span><span>Geo policy</span></div>
      </section>
      <section className="cr-chapter right" ref={setChapterRef(2)}>
        <p className="cr-kicker">02 · Gravity</p><h2>One compromised device bends everything near it.</h2>
        <p className="cr-lede">Risk Propagation Graph maps the blast radius: which accounts, devices and restricted assets sit inside the pull before the attacker reaches them.</p>
        <div className="cr-tags"><span>Risk graph</span><span>Attack paths</span><span>Asset criticality</span></div>
      </section>
      <section className="cr-chapter left" ref={setChapterRef(3)}>
        <p className="cr-kicker">03 · Judgement</p><h2>Agents investigate. Humans decide the irreversible.</h2>
        <p className="cr-lede">Investigator, Response and Learning agents work in the open, with bounded autonomy. Anything that cannot be undone waits for a recorded human approval.</p>
        <div className="cr-tags"><span>Investigator</span><span>Response</span><span>Learning</span></div>
      </section>
      <section className="cr-chapter cr-dock" ref={setChapterRef(4)}>
        <form className="cr-panel" ref={formRef} onSubmit={handleSubmit} noValidate>
          {loginStep === "password" ? <>
            <p className="cr-kicker">04 · Docking · Command access</p>
            <h2>Request clearance</h2>
            <p className="cr-sub">Authenticate to enter the control room. Your behaviour is the second factor.</p>
            <div className="cr-field"><label htmlFor="cr-username">Operator username or email</label><input id="cr-username" name="username" type="text" placeholder="username or email" autoComplete="username" spellCheck={false} autoCapitalize="none" required value={username} onChange={(event) => setUsername(event.target.value)} /></div>
            <div className="cr-field"><label htmlFor="cr-password">Passphrase</label><div className="cr-password-wrap"><input id="cr-password" name="password" type={showPassword ? "text" : "password"} placeholder="Enter your password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} /><button className="cr-eye" type="button" onClick={() => setShowPassword((visible) => !visible)} aria-label={showPassword ? "Hide passphrase" : "Show passphrase"}>{showPassword ? "Hide" : "Show"}</button></div></div>
            <button className="cr-submit" type="submit" disabled={authenticating}>{authenticating ? "Authenticating…" : "Authenticate & enter"}</button>
            <button className="cr-preview" type="button" onClick={() => navigate("/demo")}>Explore interactive preview</button>
            {!error && <p className="cr-status" role="status">{import.meta.env.DEV ? "Local demo: sumukh / sumukh@123" : ""}</p>}
          </> : <>
            <p className="cr-kicker">Second factor</p>
            <h2>Verify your authenticator</h2>
            <p className="cr-sub">Enter the 6-digit code from your authenticator app, or use a one-time backup code.</p>
            <div className="cr-field"><label htmlFor="cr-totp">Authenticator code</label><input id="cr-totp" className="cr-mfa-code" name="totp" type="text" inputMode="numeric" autoComplete="one-time-code" autoFocus maxLength={32} placeholder="000000" required value={totpCode} onChange={(event) => setTotpCode(event.target.value)} /></div>
            <button className="cr-submit" type="submit" disabled={authenticating}>{authenticating ? "Verifying code…" : "Verify & enter"}</button>
            <p className="cr-fine">Your password was accepted. Complete the authenticator check to finish signing in.</p>
          </>}
          {error && <p className="cr-status error" role="alert" aria-live="polite">{error}</p>}
          <p className="cr-fine">Demonstration software · synthetic data · first successful login establishes this browser baseline</p>
        </form>
      </section>
      <div className="cr-spacer" aria-hidden="true" />
      </main>
    </>
  );
}
