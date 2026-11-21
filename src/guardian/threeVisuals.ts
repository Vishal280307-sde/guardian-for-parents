// Lazy-loaded Three.js 3D Security Shield & 3D Family Network Globe with automatic SVG fallback

import * as THREE from 'three';
import { RoomEnvironment } from 'three/examples/jsm/environments/RoomEnvironment.js';
import { esc } from './01_core_state_and_scam_detection';

export type ShieldStatus = 'active' | 'caution' | 'alert' | 'paused' | 'offline';

export interface ShieldVisualInput {
  status: ShieldStatus;
  score: number;
  label: string;
}

export interface GlobeDeviceNode {
  id: string;
  label: string;
  role: string;
  active: boolean;
}

export interface GlobeVisualInput {
  devices: GlobeDeviceNode[];
  linkedCount: number;
  openThreatCount: number;
  caption: string;
}

export interface OrbVisualInput {
  label: string;
  sublabel: string;
}

export interface FinanceBarInput {
  label: string;
  spent: number;
  limit: number;
}

export interface FinanceVisualInput {
  bars: FinanceBarInput[];
  caption: string;
}

interface GlProbeResult {
  supported: boolean;
  isSoftwareGl: boolean;
}

let cachedGlProbe: GlProbeResult | null = null;

function detectWebGl(): GlProbeResult {
  if (cachedGlProbe) return cachedGlProbe;
  if (typeof document === 'undefined' || typeof window === 'undefined') {
    cachedGlProbe = { supported: false, isSoftwareGl: false };
    return cachedGlProbe;
  }
  try {
    const canvas = document.createElement('canvas');
    const gl =
      (canvas.getContext('webgl2', { alpha: true, antialias: true }) as WebGL2RenderingContext | null) ||
      (canvas.getContext('webgl', { alpha: true, antialias: true }) as WebGLRenderingContext | null);
    if (!gl) {
      cachedGlProbe = { supported: false, isSoftwareGl: false };
      return cachedGlProbe;
    }
    let rendererStr = '';
    const dbg = gl.getExtension('WEBGL_debug_renderer_info');
    if (dbg) {
      rendererStr = String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || '');
    }
    const isSoftwareGl = /SwiftShader|llvmpipe|softpipe|Software|Basic Render/i.test(rendererStr);
    const loseExt = gl.getExtension('WEBGL_lose_context');
    if (loseExt) loseExt.loseContext();
    cachedGlProbe = { supported: true, isSoftwareGl };
    return cachedGlProbe;
  } catch {
    cachedGlProbe = { supported: false, isSoftwareGl: false };
    return cachedGlProbe;
  }
}

function prefersReducedMotion(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
}

function afterDraw(callback: () => void, isSoftwareGl: boolean): number {
  if (isSoftwareGl) {
    return window.setTimeout(callback, 42);
  }
  return window.requestAnimationFrame(callback);
}

function cancelScheduledDraw(id: number, isSoftwareGl: boolean): void {
  if (isSoftwareGl) {
    window.clearTimeout(id);
  } else {
    window.cancelAnimationFrame(id);
  }
}

function createContactShadowTexture(): THREE.CanvasTexture {
  const c = document.createElement('canvas');
  c.width = 128;
  c.height = 128;
  const ctx = c.getContext('2d');
  if (ctx) {
    const g = ctx.createRadialGradient(64, 64, 6, 64, 64, 62);
    g.addColorStop(0, 'rgba(7, 8, 13, 0.62)');
    g.addColorStop(0.55, 'rgba(20, 16, 10, 0.24)');
    g.addColorStop(1, 'rgba(7, 8, 13, 0)');
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, 128, 128);
  }
  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  return tex;
}

const STATUS_COLORS: Record<ShieldStatus, { accent: number; emissive: number; ring: number; speed: number }> = {
  active: { accent: 0xe7c98f, emissive: 0xb68d3a, ring: 0xd4af37, speed: 0.52 },
  caution: { accent: 0xfbbf24, emissive: 0xd97706, ring: 0xf59e0b, speed: 0.42 },
  alert: { accent: 0xf87171, emissive: 0xdc2626, ring: 0xef4444, speed: 0.95 },
  paused: { accent: 0x94a3b8, emissive: 0x475569, ring: 0x94a3b8, speed: 0.16 },
  offline: { accent: 0x64748b, emissive: 0x334155, ring: 0x64748b, speed: 0.08 },
};

function renderShieldSvgFallback(container: HTMLElement, input: ShieldVisualInput): void {
  const palette =
    input.status === 'alert'
      ? { stroke: '#F87171', glow: 'rgba(239,68,68,0.28)', core: '#EF4444' }
      : input.status === 'caution'
        ? { stroke: '#FBBF24', glow: 'rgba(245,158,11,0.25)', core: '#F59E0B' }
        : input.status === 'paused' || input.status === 'offline'
          ? { stroke: '#94A3B8', glow: 'rgba(148,163,184,0.2)', core: '#64748B' }
          : { stroke: '#E7C98F', glow: 'rgba(212,175,55,0.32)', core: '#D4AF37' };

  container.innerHTML = `<div style="position:relative;width:100%;height:100%;display:flex;align-items:center;justify-content:center;padding:18px 14px 36px">
    <svg width="136" height="148" viewBox="0 0 136 148" fill="none" aria-hidden="true" style="filter:drop-shadow(0 12px 24px ${palette.glow})">
      <circle cx="68" cy="72" r="58" stroke="${palette.stroke}" stroke-opacity="0.28" stroke-width="1.5" stroke-dasharray="5 5"/>
      <ellipse cx="68" cy="72" rx="62" ry="24" transform="rotate(-18 68 72)" stroke="${palette.stroke}" stroke-opacity="0.48" stroke-width="1.6"/>
      <path d="M68 14L114 32V68C114 98 94 122 68 134C42 122 22 98 22 68V32L68 14Z" fill="#07080D" stroke="${palette.stroke}" stroke-width="2.4"/>
      <path d="M68 25L103 39V67C103 90 88 109 68 119C48 109 33 90 33 67V39L68 25Z" fill="#0D1B35" stroke="${palette.core}" stroke-opacity="0.75" stroke-width="1.5"/>
      <path d="M54 71L64 81L85 58" stroke="${palette.stroke}" stroke-width="4.5" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <div class="stage-3d-caption"><span>3D Shield · ${esc(input.label)}</span><span class="num">${esc(input.score)}/100</span></div>
  </div>`;
}

function renderOrbSvgFallback(container: HTMLElement, input: OrbVisualInput): void {
  container.innerHTML = `<div style="position:relative;width:100%;height:100%;display:flex;align-items:center;justify-content:center;padding:16px 14px 36px">
    <svg width="150" height="150" viewBox="0 0 150 150" fill="none" aria-hidden="true" style="filter:drop-shadow(0 14px 28px rgba(212,175,55,0.34))">
      <defs>
        <radialGradient id="goldOrbG" cx="35%" cy="30%" r="70%">
          <stop offset="0%" stop-color="#FAF6EE"/>
          <stop offset="45%" stop-color="#E7C98F"/>
          <stop offset="85%" stop-color="#B68D3A"/>
          <stop offset="100%" stop-color="#5E4518"/>
        </radialGradient>
      </defs>
      <ellipse cx="75" cy="75" rx="64" ry="22" transform="rotate(-20 75 75)" stroke="#E7C98F" stroke-opacity="0.55" stroke-width="1.6"/>
      <ellipse cx="75" cy="75" rx="56" ry="18" transform="rotate(25 75 75)" stroke="#8B5CF6" stroke-opacity="0.4" stroke-width="1.3"/>
      <circle cx="75" cy="75" r="34" fill="url(#goldOrbG)" stroke="#FAF6EE" stroke-opacity="0.5"/>
    </svg>
    <div class="stage-3d-caption"><span>${esc(input.label)}</span><span>${esc(input.sublabel)}</span></div>
  </div>`;
}

function renderGlobeSvgFallback(container: HTMLElement, input: GlobeVisualInput): void {
  const activeCount = input.devices.filter((d) => d.active).length;
  const threatStroke = input.openThreatCount > 0 ? '#F87171' : '#E7C98F';
  container.innerHTML = `<div style="position:relative;width:100%;height:100%;display:flex;align-items:center;justify-content:center;padding:16px 14px 38px">
    <svg width="160" height="160" viewBox="0 0 160 160" fill="none" aria-hidden="true">
      <circle cx="80" cy="80" r="56" fill="#07080D" stroke="#D4AF37" stroke-width="2"/>
      <ellipse cx="80" cy="80" rx="56" ry="20" stroke="#E7C98F" stroke-opacity="0.45" stroke-width="1.3"/>
      <ellipse cx="80" cy="80" rx="22" ry="56" stroke="#E7C98F" stroke-opacity="0.45" stroke-width="1.3"/>
      <path d="M36 62C64 26 106 30 124 66" stroke="${threatStroke}" stroke-width="2" stroke-linecap="round"/>
      <circle cx="36" cy="62" r="4.5" fill="#E7C98F"/>
      <circle cx="124" cy="66" r="4.5" fill="${input.openThreatCount > 0 ? '#F87171' : '#10B981'}"/>
      <circle cx="80" cy="106" r="4.5" fill="#E7C98F"/>
    </svg>
    <div class="stage-3d-caption"><span>${esc(input.caption)}</span><span class="num">${activeCount} device(s) · ${input.linkedCount} linked</span></div>
  </div>`;
}

function renderFinanceSvgFallback(container: HTMLElement, input: FinanceVisualInput): void {
  const bars = input.bars.slice(0, 5);
  const maxVal = Math.max(1, ...bars.map((b) => Math.max(b.spent, b.limit)));
  container.innerHTML = `<div style="position:relative;width:100%;height:100%;display:flex;flex-direction:column;justify-content:center;padding:18px 20px 42px">
    <div style="display:flex;align-items:flex-end;justify-content:space-around;gap:12px;height:130px;padding-bottom:8px;border-bottom:1px solid rgba(212,175,55,0.28)">
      ${
        bars.length
          ? bars
              .map((b) => {
                const h = Math.max(14, Math.round((b.spent / maxVal) * 110));
                return `<div style="display:flex;flex-direction:column;align-items:center;gap:6px;flex:1">
                  <div style="width:24px;height:${h}px;border-radius:6px 6px 2px 2px;background:linear-gradient(180deg,#E7C98F,#B68D3A)"></div>
                  <span style="font-size:11px;color:#F3EAD8">${esc(b.label.slice(0, 8))}</span>
                </div>`;
              })
              .join('')
          : '<span style="color:#C9BFA9;font-size:13px">Connect Sample Demo Bank to render 3D financial bars</span>'
      }
    </div>
    <div class="stage-3d-caption"><span>${esc(input.caption)}</span><span class="num">${bars.length} category bars</span></div>
  </div>`;
}

class ShieldController {
  readonly canvas: HTMLCanvasElement;
  private renderer: THREE.WebGLRenderer;
  private scene: THREE.Scene;
  private camera: THREE.PerspectiveCamera;
  private pmrem: THREE.PMREMGenerator;
  private envRT: THREE.WebGLRenderTarget;
  private group: THREE.Group;
  private innerCrest: THREE.Mesh;
  private ringA: THREE.Mesh;
  private ringB: THREE.Mesh;
  private coreMat: THREE.MeshStandardMaterial;
  private ringMat: THREE.MeshStandardMaterial;
  private particlesMat: THREE.PointsMaterial;
  private shadowTex: THREE.CanvasTexture;
  private isSoftwareGl: boolean;
  private frameId = 0;
  private disposed = false;
  private status: ShieldStatus = 'active';
  private pointerX = 0;
  private pointerY = 0;
  private targetAccent = new THREE.Color(0x35d5f5);
  private targetEmissive = new THREE.Color(0x2878ff);
  private targetRing = new THREE.Color(0x35d5f5);
  private currentSpeed = 0.55;
  private lastTick = performance.now();
  private elapsed = 0;
  private attachedHost: HTMLElement | null = null;
  private resizeObserver: ResizeObserver | null = null;

  constructor(isSoftwareGl: boolean) {
    this.isSoftwareGl = isSoftwareGl;
    this.canvas = document.createElement('canvas');
    this.canvas.className = 'stage-3d-canvas';
    this.canvas.setAttribute('aria-label', 'Interactive 3D security shield');

    this.renderer = new THREE.WebGLRenderer({
      canvas: this.canvas,
      antialias: !isSoftwareGl,
      alpha: true,
      powerPreference: 'high-performance',
    });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, isSoftwareGl ? 1 : 2));
    this.renderer.toneMapping = THREE.ACESFilmicToneMapping;
    this.renderer.toneMappingExposure = 1.08;

    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(36, 1.4, 0.1, 40);
    this.camera.position.set(0, 0.28, 5.4);
    this.camera.lookAt(0, 0, 0);

    this.pmrem = new THREE.PMREMGenerator(this.renderer);
    const room = new RoomEnvironment();
    this.envRT = this.pmrem.fromScene(room, 0.04);
    room.dispose();
    this.scene.environment = this.envRT.texture;
    this.scene.environmentIntensity = 0.72;

    const keyLight = new THREE.DirectionalLight(0xfaf6ee, 1.8);
    keyLight.position.set(3.2, 4.4, 4.2);
    this.scene.add(keyLight);

    const rimLight = new THREE.DirectionalLight(0xe7c98f, 1.35);
    rimLight.position.set(-4.0, 1.6, -2.5);
    this.scene.add(rimLight);

    this.group = new THREE.Group();
    this.scene.add(this.group);

    // Outer beveled metallic obsidian shield body
    const shieldShape = new THREE.Shape();
    shieldShape.moveTo(0, 1.32);
    shieldShape.quadraticCurveTo(0.95, 1.08, 1.12, 0.72);
    shieldShape.quadraticCurveTo(1.1, -0.38, 0, -1.35);
    shieldShape.quadraticCurveTo(-1.1, -0.38, -1.12, 0.72);
    shieldShape.quadraticCurveTo(-0.95, 1.08, 0, 1.32);

    const outerGeo = new THREE.ExtrudeGeometry(shieldShape, {
      depth: 0.16,
      bevelEnabled: true,
      bevelThickness: 0.07,
      bevelSize: 0.06,
      bevelSegments: 3,
      curveSegments: 20,
    });
    outerGeo.center();

    const outerMat = new THREE.MeshPhysicalMaterial({
      color: 0x0b1322,
      metalness: 0.82,
      roughness: 0.22,
      clearcoat: 0.72,
      clearcoatRoughness: 0.16,
    });
    const outerMesh = new THREE.Mesh(outerGeo, outerMat);
    this.group.add(outerMesh);

    // Inner recessed shield bezel
    const innerGeo = new THREE.ExtrudeGeometry(shieldShape, {
      depth: 0.08,
      bevelEnabled: true,
      bevelThickness: 0.03,
      bevelSize: 0.02,
      bevelSegments: 2,
      curveSegments: 16,
    });
    innerGeo.center();
    const innerPlateMat = new THREE.MeshStandardMaterial({
      color: 0x16243d,
      metalness: 0.65,
      roughness: 0.28,
    });
    const innerPlate = new THREE.Mesh(innerGeo, innerPlateMat);
    innerPlate.scale.set(0.76, 0.76, 1.25);
    innerPlate.position.z = 0.09;
    this.group.add(innerPlate);

    // Faceted champagne-gold security status crystal crest at center
    this.coreMat = new THREE.MeshStandardMaterial({
      color: 0xe7c98f,
      emissive: 0xb68d3a,
      emissiveIntensity: 0.75,
      metalness: 0.75,
      roughness: 0.16,
    });
    const crestGeo = new THREE.OctahedronGeometry(0.42, 0);
    this.innerCrest = new THREE.Mesh(crestGeo, this.coreMat);
    this.innerCrest.position.set(0, 0.06, 0.28);
    this.innerCrest.scale.set(0.95, 1.22, 0.65);
    this.group.add(this.innerCrest);

    // Dual protective orbital champagne torus rings
    this.ringMat = new THREE.MeshStandardMaterial({
      color: 0xd4af37,
      emissive: 0x8c6d3f,
      emissiveIntensity: 0.42,
      metalness: 0.85,
      roughness: 0.2,
    });
    const torusGeoA = new THREE.TorusGeometry(1.56, 0.024, 12, 64);
    this.ringA = new THREE.Mesh(torusGeoA, this.ringMat);
    this.ringA.rotation.set(Math.PI * 0.38, Math.PI * 0.14, 0);
    this.group.add(this.ringA);

    const torusGeoB = new THREE.TorusGeometry(1.78, 0.018, 10, 64);
    this.ringB = new THREE.Mesh(torusGeoB, this.ringMat);
    this.ringB.rotation.set(-Math.PI * 0.32, Math.PI * 0.28, 0);
    this.group.add(this.ringB);

    // Golden constellation particles
    const count = 48;
    const pts = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
      const a = (i / count) * Math.PI * 2;
      const r = 1.65 + (i % 5) * 0.16;
      pts[i * 3] = Math.cos(a) * r;
      pts[i * 3 + 1] = ((i % 7) - 3) * 0.42;
      pts[i * 3 + 2] = Math.sin(a) * r * 0.6;
    }
    const ptsGeo = new THREE.BufferGeometry();
    ptsGeo.setAttribute('position', new THREE.BufferAttribute(pts, 3));
    this.particlesMat = new THREE.PointsMaterial({
      color: 0xe7c98f,
      size: 0.048,
      transparent: true,
      opacity: 0.78,
    });
    const particles = new THREE.Points(ptsGeo, this.particlesMat);
    this.group.add(particles);

    // Soft contact shadow plane underneath
    this.shadowTex = createContactShadowTexture();
    const shadowGeo = new THREE.PlaneGeometry(3.1, 1.4);
    const shadowMat = new THREE.MeshBasicMaterial({
      map: this.shadowTex,
      transparent: true,
      depthWrite: false,
      opacity: 0.8,
    });
    const shadowMesh = new THREE.Mesh(shadowGeo, shadowMat);
    shadowMesh.rotation.x = -Math.PI / 2;
    shadowMesh.position.set(0, -1.65, 0);
    this.scene.add(shadowMesh);

    this.canvas.addEventListener('pointermove', this.onPointerMove, { passive: true });
    this.canvas.addEventListener('pointerleave', this.onPointerLeave, { passive: true });
    this.canvas.addEventListener('webglcontextlost', this.onContextLost);

    this.resizeObserver = new ResizeObserver(() => this.resize());
  }

  private onPointerMove = (e: PointerEvent) => {
    const r = this.canvas.getBoundingClientRect();
    if (r.width <= 0 || r.height <= 0) return;
    this.pointerX = ((e.clientX - r.left) / r.width - 0.5) * 2;
    this.pointerY = ((e.clientY - r.top) / r.height - 0.5) * 2;
  };

  private onPointerLeave = () => {
    this.pointerX = 0;
    this.pointerY = 0;
  };

  private onContextLost = (e: Event) => {
    e.preventDefault();
    this.dispose();
  };

  attach(host: HTMLElement, input: ShieldVisualInput): void {
    if (this.disposed) return;
    this.status = input.status;
    const preset = STATUS_COLORS[input.status];
    this.targetAccent.setHex(preset.accent);
    this.targetEmissive.setHex(preset.emissive);
    this.targetRing.setHex(preset.ring);

    if (this.attachedHost !== host) {
      if (this.attachedHost) {
        this.resizeObserver?.unobserve(this.attachedHost);
      }
      host.innerHTML = '';
      host.appendChild(this.canvas);
      const caption = document.createElement('div');
      caption.className = 'stage-3d-caption';
      caption.innerHTML = `<span>3D Shield · ${esc(input.label)}</span><span class="num">${esc(input.score)}/100</span>`;
      host.appendChild(caption);
      this.attachedHost = host;
      this.resizeObserver?.observe(host);
    } else {
      const caption = host.querySelector('.stage-3d-caption');
      if (caption) {
        caption.innerHTML = `<span>3D Shield · ${esc(input.label)}</span><span class="num">${esc(input.score)}/100</span>`;
      }
    }

    this.resize();
    if (!this.frameId) {
      this.lastTick = performance.now();
      this.scheduleNext();
    }
  }

  private resize(): void {
    if (!this.attachedHost || this.disposed) return;
    const w = Math.max(200, this.attachedHost.clientWidth || 300);
    const h = Math.max(180, this.attachedHost.clientHeight || 220);
    this.renderer.setSize(w, h, false);
    this.camera.aspect = w / h;
    this.camera.updateProjectionMatrix();
  }

  private scheduleNext(): void {
    if (this.disposed) return;
    this.frameId = afterDraw(this.renderFrame, this.isSoftwareGl);
  }

  private renderFrame = (): void => {
    if (this.disposed) return;
    if (!document.body.contains(this.canvas)) {
      this.frameId = 0;
      return;
    }
    const now = performance.now();
    const dt = Math.min(0.08, Math.max(0.001, (now - this.lastTick) / 1000));
    this.lastTick = now;

    const preset = STATUS_COLORS[this.status];
    this.currentSpeed = THREE.MathUtils.damp(this.currentSpeed, preset.speed, 4.0, dt);
    this.elapsed += dt * this.currentSpeed;

    this.coreMat.color.lerp(this.targetAccent, Math.min(1, dt * 5));
    this.coreMat.emissive.lerp(this.targetEmissive, Math.min(1, dt * 5));
    this.ringMat.color.lerp(this.targetRing, Math.min(1, dt * 5));
    this.ringMat.emissive.lerp(this.targetEmissive, Math.min(1, dt * 5));
    this.particlesMat.color.lerp(this.targetAccent, Math.min(1, dt * 4));

    // Gentle hover & protective motion
    const targetRotY = this.pointerX * 0.34 + Math.sin(this.elapsed * 0.9) * 0.22;
    const targetRotX = this.pointerY * 0.22 + Math.cos(this.elapsed * 0.65) * 0.08;
    this.group.rotation.y = THREE.MathUtils.damp(this.group.rotation.y, targetRotY, 5.5, dt);
    this.group.rotation.x = THREE.MathUtils.damp(this.group.rotation.x, targetRotX, 5.5, dt);
    this.group.position.y = Math.sin(this.elapsed * 1.6) * 0.07;

    this.innerCrest.rotation.y = this.elapsed * 1.4;
    this.ringA.rotation.z += dt * (this.currentSpeed * 0.75);
    this.ringB.rotation.z -= dt * (this.currentSpeed * 0.55);

    this.renderer.render(this.scene, this.camera);
    this.scheduleNext();
  };

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    if (this.frameId) {
      cancelScheduledDraw(this.frameId, this.isSoftwareGl);
      this.frameId = 0;
    }
    this.resizeObserver?.disconnect();
    this.canvas.removeEventListener('pointermove', this.onPointerMove);
    this.canvas.removeEventListener('pointerleave', this.onPointerLeave);
    this.canvas.removeEventListener('webglcontextlost', this.onContextLost);
    this.scene.traverse((obj) => {
      if (obj instanceof THREE.Mesh || obj instanceof THREE.Points) {
        obj.geometry.dispose();
        const mats = Array.isArray(obj.material) ? obj.material : [obj.material];
        mats.forEach((m) => m.dispose());
      }
    });
    this.shadowTex.dispose();
    this.envRT.dispose();
    this.pmrem.dispose();
    this.renderer.dispose();
  }
}

class GlobeController {
  readonly canvas: HTMLCanvasElement;
  private renderer: THREE.WebGLRenderer;
  private scene: THREE.Scene;
  private camera: THREE.PerspectiveCamera;
  private pmrem: THREE.PMREMGenerator;
  private envRT: THREE.WebGLRenderTarget;
  private globeGroup: THREE.Group;
  private dynamicGroup: THREE.Group;
  private scanBand: THREE.Mesh;
  private isSoftwareGl: boolean;
  private frameId = 0;
  private disposed = false;
  private attachedHost: HTMLElement | null = null;
  private resizeObserver: ResizeObserver | null = null;
  private lastDataSig = '';
  private dragging = false;
  private lastX = 0;
  private lastY = 0;
  private userVelY = 0;
  private userRotX = 0.22;
  private lastTick = performance.now();

  constructor(isSoftwareGl: boolean) {
    this.isSoftwareGl = isSoftwareGl;
    this.canvas = document.createElement('canvas');
    this.canvas.className = 'stage-3d-canvas';
    this.canvas.style.cursor = 'grab';
    this.canvas.setAttribute('aria-label', 'Interactive 3D family security network globe');

    this.renderer = new THREE.WebGLRenderer({
      canvas: this.canvas,
      antialias: !isSoftwareGl,
      alpha: true,
      powerPreference: 'high-performance',
    });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, isSoftwareGl ? 1 : 2));
    this.renderer.toneMapping = THREE.ACESFilmicToneMapping;
    this.renderer.toneMappingExposure = 1.05;

    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(38, 1.5, 0.1, 40);
    this.camera.position.set(0, 0.15, 4.9);
    this.camera.lookAt(0, 0, 0);

    this.pmrem = new THREE.PMREMGenerator(this.renderer);
    const room = new RoomEnvironment();
    this.envRT = this.pmrem.fromScene(room, 0.04);
    room.dispose();
    this.scene.environment = this.envRT.texture;
    this.scene.environmentIntensity = 0.65;

    const key = new THREE.DirectionalLight(0xfaf6ee, 1.5);
    key.position.set(3, 3.5, 4);
    this.scene.add(key);

    const rim = new THREE.DirectionalLight(0xd4af37, 1.25);
    rim.position.set(-4, -1, -3);
    this.scene.add(rim);

    this.globeGroup = new THREE.Group();
    this.scene.add(this.globeGroup);

    // Core deep-obsidian sphere + champagne gold meridian lattice
    const sphereGeo = new THREE.SphereGeometry(1.36, 24, 18);
    const sphereMat = new THREE.MeshPhysicalMaterial({
      color: 0x0a1324,
      metalness: 0.52,
      roughness: 0.28,
      clearcoat: 0.55,
      transparent: true,
      opacity: 0.94,
    });
    this.globeGroup.add(new THREE.Mesh(sphereGeo, sphereMat));

    const wireGeo = new THREE.EdgesGeometry(new THREE.SphereGeometry(1.385, 16, 12));
    const wireMat = new THREE.LineBasicMaterial({
      color: 0xd4af37,
      transparent: true,
      opacity: 0.32,
    });
    this.globeGroup.add(new THREE.LineSegments(wireGeo, wireMat));

    // Equatorial champagne ring
    const bandGeo = new THREE.TorusGeometry(1.66, 0.016, 10, 64);
    const bandMat = new THREE.MeshStandardMaterial({
      color: 0xc9a96e,
      emissive: 0x8c6d3f,
      emissiveIntensity: 0.42,
    });
    this.scanBand = new THREE.Mesh(bandGeo, bandMat);
    this.scanBand.rotation.x = Math.PI * 0.46;
    this.globeGroup.add(this.scanBand);

    this.dynamicGroup = new THREE.Group();
    this.globeGroup.add(this.dynamicGroup);

    this.canvas.addEventListener('pointerdown', this.onDown);
    window.addEventListener('pointermove', this.onMove, { passive: true });
    window.addEventListener('pointerup', this.onUp, { passive: true });
    this.canvas.addEventListener('webglcontextlost', this.onLost);

    this.resizeObserver = new ResizeObserver(() => this.resize());
  }

  private onDown = (e: PointerEvent) => {
    this.dragging = true;
    this.lastX = e.clientX;
    this.lastY = e.clientY;
    this.canvas.style.cursor = 'grabbing';
  };

  private onMove = (e: PointerEvent) => {
    if (!this.dragging) return;
    const dx = e.clientX - this.lastX;
    const dy = e.clientY - this.lastY;
    this.lastX = e.clientX;
    this.lastY = e.clientY;
    this.globeGroup.rotation.y += dx * 0.008;
    this.userVelY = dx * 0.015;
    this.userRotX = Math.max(-0.55, Math.min(0.65, this.userRotX + dy * 0.006));
  };

  private onUp = () => {
    this.dragging = false;
    this.canvas.style.cursor = 'grab';
  };

  private onLost = (e: Event) => {
    e.preventDefault();
    this.dispose();
  };

  private rebuildNetworkNodes(input: GlobeVisualInput): void {
    const sig = `${input.devices.map((d) => `${d.id}:${d.active}`).join(',')}|${input.linkedCount}|${input.openThreatCount}`;
    if (sig === this.lastDataSig) return;
    this.lastDataSig = sig;

    while (this.dynamicGroup.children.length > 0) {
      const ch = this.dynamicGroup.children[0];
      this.dynamicGroup.remove(ch);
      if (ch instanceof THREE.Mesh) {
        ch.geometry.dispose();
        const mats = Array.isArray(ch.material) ? ch.material : [ch.material];
        mats.forEach((m) => m.dispose());
      }
    }

    const totalNodes = Math.max(1, Math.min(10, input.devices.length + Math.min(4, input.linkedCount)));
    const coords: THREE.Vector3[] = [];
    const radius = 1.41;

    for (let i = 0; i < totalNodes; i++) {
      const phi = Math.acos(1 - (2 * (i + 0.5)) / totalNodes);
      const theta = Math.PI * (1 + Math.sqrt(5)) * i;
      const v = new THREE.Vector3(
        radius * Math.sin(phi) * Math.cos(theta),
        radius * Math.cos(phi),
        radius * Math.sin(phi) * Math.sin(theta)
      );
      coords.push(v);

      const dev = input.devices[i];
      const isAlertNode = input.openThreatCount > 0 && i === 0;
      const isActive = dev ? dev.active : true;
      const colorHex = isAlertNode ? 0xf87171 : isActive ? 0xe7c98f : 0x94a3b8;

      const nodeGeo = new THREE.SphereGeometry(isAlertNode ? 0.075 : 0.058, 12, 10);
      const nodeMat = new THREE.MeshStandardMaterial({
        color: colorHex,
        emissive: colorHex,
        emissiveIntensity: isAlertNode ? 0.95 : 0.55,
      });
      const mesh = new THREE.Mesh(nodeGeo, nodeMat);
      mesh.position.copy(v);
      this.dynamicGroup.add(mesh);
    }

    // Connect real family network arcs when > 1 node exists
    for (let i = 1; i < coords.length; i++) {
      const start = coords[0];
      const end = coords[i];
      const mid = start.clone().add(end).multiplyScalar(0.5).normalize().multiplyScalar(1.88);
      const curve = new THREE.QuadraticBezierCurve3(start, mid, end);
      const tubeGeo = new THREE.TubeGeometry(curve, 18, 0.012, 6, false);
      const isThreatArc = input.openThreatCount > 0 && i === 1;
      const tubeMat = new THREE.MeshBasicMaterial({
        color: isThreatArc ? 0xf87171 : 0xd4af37,
        transparent: true,
        opacity: isThreatArc ? 0.9 : 0.68,
      });
      this.dynamicGroup.add(new THREE.Mesh(tubeGeo, tubeMat));
    }
  }

  attach(host: HTMLElement, input: GlobeVisualInput): void {
    if (this.disposed) return;
    this.rebuildNetworkNodes(input);
    const activeCount = input.devices.filter((d) => d.active).length;
    const captionHtml = `<span>${esc(input.caption)} (drag to inspect)</span><span class="num">${activeCount} device(s) · ${input.linkedCount} linked · ${input.openThreatCount} active alert(s)</span>`;

    if (this.attachedHost !== host) {
      if (this.attachedHost) {
        this.resizeObserver?.unobserve(this.attachedHost);
      }
      host.innerHTML = '';
      host.appendChild(this.canvas);
      const caption = document.createElement('div');
      caption.className = 'stage-3d-caption';
      caption.innerHTML = captionHtml;
      host.appendChild(caption);
      this.attachedHost = host;
      this.resizeObserver?.observe(host);
    } else {
      const cap = host.querySelector('.stage-3d-caption');
      if (cap) cap.innerHTML = captionHtml;
    }

    this.resize();
    if (!this.frameId) {
      this.lastTick = performance.now();
      this.scheduleNext();
    }
  }

  private resize(): void {
    if (!this.attachedHost || this.disposed) return;
    const w = Math.max(220, this.attachedHost.clientWidth || 320);
    const h = Math.max(220, this.attachedHost.clientHeight || 255);
    this.renderer.setSize(w, h, false);
    this.camera.aspect = w / h;
    this.camera.updateProjectionMatrix();
  }

  private scheduleNext(): void {
    if (this.disposed) return;
    this.frameId = afterDraw(this.renderFrame, this.isSoftwareGl);
  }

  private renderFrame = (): void => {
    if (this.disposed) return;
    if (!document.body.contains(this.canvas)) {
      this.frameId = 0;
      return;
    }
    const now = performance.now();
    const dt = Math.min(0.08, Math.max(0.001, (now - this.lastTick) / 1000));
    this.lastTick = now;

    if (!this.dragging) {
      this.userVelY = THREE.MathUtils.damp(this.userVelY, 0, 4.2, dt);
      this.globeGroup.rotation.y += dt * 0.24 + this.userVelY * dt * 12;
    }
    this.globeGroup.rotation.x = THREE.MathUtils.damp(this.globeGroup.rotation.x, this.userRotX, 6, dt);
    this.scanBand.rotation.z += dt * 0.45;

    this.renderer.render(this.scene, this.camera);
    this.scheduleNext();
  };

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    if (this.frameId) {
      cancelScheduledDraw(this.frameId, this.isSoftwareGl);
      this.frameId = 0;
    }
    this.resizeObserver?.disconnect();
    this.canvas.removeEventListener('pointerdown', this.onDown);
    window.removeEventListener('pointermove', this.onMove);
    window.removeEventListener('pointerup', this.onUp);
    this.canvas.removeEventListener('webglcontextlost', this.onLost);
    this.scene.traverse((obj) => {
      if (obj instanceof THREE.Mesh || obj instanceof THREE.LineSegments) {
        obj.geometry.dispose();
        const mats = Array.isArray(obj.material) ? obj.material : [obj.material];
        mats.forEach((m) => m.dispose());
      }
    });
    this.envRT.dispose();
    this.pmrem.dispose();
    this.renderer.dispose();
  }
}

class OrbController {
  readonly canvas: HTMLCanvasElement;
  private renderer: THREE.WebGLRenderer;
  private scene: THREE.Scene;
  private camera: THREE.PerspectiveCamera;
  private pmrem: THREE.PMREMGenerator;
  private envRT: THREE.WebGLRenderTarget;
  private group: THREE.Group;
  private ringOuter: THREE.Mesh;
  private ringInner: THREE.Mesh;
  private haloPoints: THREE.Points;
  private isSoftwareGl: boolean;
  private frameId = 0;
  private disposed = false;
  private pointerX = 0;
  private pointerY = 0;
  private elapsed = 0;
  private lastTick = performance.now();
  private attachedHost: HTMLElement | null = null;
  private resizeObserver: ResizeObserver | null = null;

  constructor(isSoftwareGl: boolean) {
    this.isSoftwareGl = isSoftwareGl;
    this.canvas = document.createElement('canvas');
    this.canvas.className = 'stage-3d-canvas';
    this.canvas.setAttribute('aria-label', 'Interactive Metallic Golden AI Assistant Orb');

    this.renderer = new THREE.WebGLRenderer({
      canvas: this.canvas,
      antialias: !isSoftwareGl,
      alpha: true,
      powerPreference: 'high-performance',
    });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, isSoftwareGl ? 1 : 2));
    this.renderer.toneMapping = THREE.ACESFilmicToneMapping;
    this.renderer.toneMappingExposure = 1.12;

    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(36, 1.35, 0.1, 40);
    this.camera.position.set(0, 0.15, 4.8);
    this.camera.lookAt(0, 0, 0);

    this.pmrem = new THREE.PMREMGenerator(this.renderer);
    const room = new RoomEnvironment();
    this.envRT = this.pmrem.fromScene(room, 0.04);
    room.dispose();
    this.scene.environment = this.envRT.texture;
    this.scene.environmentIntensity = 0.85;

    const key = new THREE.DirectionalLight(0xfaf6ee, 2.0);
    key.position.set(3.2, 4.0, 4.0);
    this.scene.add(key);

    const purpleRim = new THREE.DirectionalLight(0x8b5cf6, 0.9);
    purpleRim.position.set(-3.8, -1.2, -2.6);
    this.scene.add(purpleRim);

    this.group = new THREE.Group();
    this.scene.add(this.group);

    // Metallic brushed champagne-gold core orb
    const sphereGeo = new THREE.SphereGeometry(0.92, 42, 32);
    const orbMat = new THREE.MeshPhysicalMaterial({
      color: 0xd4af37,
      metalness: 0.92,
      roughness: 0.16,
      clearcoat: 0.9,
      clearcoatRoughness: 0.12,
      anisotropy: 0.72,
    });
    this.group.add(new THREE.Mesh(sphereGeo, orbMat));

    // Dual gyro rings
    const ringMatGold = new THREE.MeshStandardMaterial({
      color: 0xe7c98f,
      emissive: 0x8c6d3f,
      emissiveIntensity: 0.35,
      metalness: 0.88,
      roughness: 0.2,
    });
    this.ringOuter = new THREE.Mesh(new THREE.TorusGeometry(1.38, 0.024, 12, 72), ringMatGold);
    this.ringOuter.rotation.set(Math.PI * 0.35, Math.PI * 0.12, 0);
    this.group.add(this.ringOuter);

    const ringMatPurple = new THREE.MeshStandardMaterial({
      color: 0xa78bfa,
      emissive: 0x6d28d9,
      emissiveIntensity: 0.35,
      metalness: 0.7,
      roughness: 0.25,
    });
    this.ringInner = new THREE.Mesh(new THREE.TorusGeometry(1.18, 0.016, 10, 64), ringMatPurple);
    this.ringInner.rotation.set(-Math.PI * 0.28, Math.PI * 0.34, 0);
    this.group.add(this.ringInner);

    // Floating golden dust particles
    const count = 64;
    const pts = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
      const a = (i / count) * Math.PI * 2;
      const r = 1.45 + (i % 6) * 0.14;
      pts[i * 3] = Math.cos(a) * r;
      pts[i * 3 + 1] = Math.sin(i * 1.3) * 0.85;
      pts[i * 3 + 2] = Math.sin(a) * r * 0.7;
    }
    const ptsGeo = new THREE.BufferGeometry();
    ptsGeo.setAttribute('position', new THREE.BufferAttribute(pts, 3));
    this.haloPoints = new THREE.Points(
      ptsGeo,
      new THREE.PointsMaterial({ color: 0xe7c98f, size: 0.045, transparent: true, opacity: 0.82 })
    );
    this.group.add(this.haloPoints);

    this.canvas.addEventListener('pointermove', this.onMove, { passive: true });
    this.canvas.addEventListener('pointerleave', this.onLeave, { passive: true });
    this.canvas.addEventListener('webglcontextlost', this.onLost);
    this.resizeObserver = new ResizeObserver(() => this.resize());
  }

  private onMove = (e: PointerEvent) => {
    const r = this.canvas.getBoundingClientRect();
    if (r.width <= 0 || r.height <= 0) return;
    this.pointerX = ((e.clientX - r.left) / r.width - 0.5) * 2;
    this.pointerY = ((e.clientY - r.top) / r.height - 0.5) * 2;
  };

  private onLeave = () => {
    this.pointerX = 0;
    this.pointerY = 0;
  };

  private onLost = (e: Event) => {
    e.preventDefault();
    this.dispose();
  };

  attach(host: HTMLElement, input: OrbVisualInput): void {
    if (this.disposed) return;
    const capHtml = `<span>${esc(input.label)}</span><span>${esc(input.sublabel)}</span>`;
    if (this.attachedHost !== host) {
      if (this.attachedHost) this.resizeObserver?.unobserve(this.attachedHost);
      host.innerHTML = '';
      host.appendChild(this.canvas);
      const caption = document.createElement('div');
      caption.className = 'stage-3d-caption';
      caption.innerHTML = capHtml;
      host.appendChild(caption);
      this.attachedHost = host;
      this.resizeObserver?.observe(host);
    } else {
      const cap = host.querySelector('.stage-3d-caption');
      if (cap) cap.innerHTML = capHtml;
    }
    this.resize();
    if (!this.frameId) {
      this.lastTick = performance.now();
      this.scheduleNext();
    }
  }

  private resize(): void {
    if (!this.attachedHost || this.disposed) return;
    const w = Math.max(200, this.attachedHost.clientWidth || 300);
    const h = Math.max(180, this.attachedHost.clientHeight || 225);
    this.renderer.setSize(w, h, false);
    this.camera.aspect = w / h;
    this.camera.updateProjectionMatrix();
  }

  private scheduleNext(): void {
    if (this.disposed) return;
    this.frameId = afterDraw(this.renderFrame, this.isSoftwareGl);
  }

  private renderFrame = (): void => {
    if (this.disposed) return;
    if (!document.body.contains(this.canvas)) {
      this.frameId = 0;
      return;
    }
    const now = performance.now();
    const dt = Math.min(0.08, Math.max(0.001, (now - this.lastTick) / 1000));
    this.lastTick = now;
    this.elapsed += dt;

    this.group.rotation.y = THREE.MathUtils.damp(this.group.rotation.y, this.pointerX * 0.4 + Math.sin(this.elapsed * 0.5) * 0.25, 5, dt);
    this.group.rotation.x = THREE.MathUtils.damp(this.group.rotation.x, this.pointerY * 0.25, 5, dt);
    this.group.position.y = Math.sin(this.elapsed * 1.5) * 0.08;
    this.ringOuter.rotation.z += dt * 0.6;
    this.ringInner.rotation.z -= dt * 0.82;
    this.haloPoints.rotation.y += dt * 0.18;

    this.renderer.render(this.scene, this.camera);
    this.scheduleNext();
  };

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    if (this.frameId) {
      cancelScheduledDraw(this.frameId, this.isSoftwareGl);
      this.frameId = 0;
    }
    this.resizeObserver?.disconnect();
    this.canvas.removeEventListener('pointermove', this.onMove);
    this.canvas.removeEventListener('pointerleave', this.onLeave);
    this.canvas.removeEventListener('webglcontextlost', this.onLost);
    this.scene.traverse((obj) => {
      if (obj instanceof THREE.Mesh || obj instanceof THREE.Points) {
        obj.geometry.dispose();
        const mats = Array.isArray(obj.material) ? obj.material : [obj.material];
        mats.forEach((m) => m.dispose());
      }
    });
    this.envRT.dispose();
    this.pmrem.dispose();
    this.renderer.dispose();
  }
}

class FinanceChartController {
  readonly canvas: HTMLCanvasElement;
  private renderer: THREE.WebGLRenderer;
  private scene: THREE.Scene;
  private camera: THREE.PerspectiveCamera;
  private pmrem: THREE.PMREMGenerator;
  private envRT: THREE.WebGLRenderTarget;
  private group: THREE.Group;
  private isSoftwareGl: boolean;
  private frameId = 0;
  private disposed = false;
  private lastSig = '';
  private pointerX = 0;
  private elapsed = 0;
  private lastTick = performance.now();
  private attachedHost: HTMLElement | null = null;
  private resizeObserver: ResizeObserver | null = null;

  constructor(isSoftwareGl: boolean) {
    this.isSoftwareGl = isSoftwareGl;
    this.canvas = document.createElement('canvas');
    this.canvas.className = 'stage-3d-canvas';
    this.canvas.setAttribute('aria-label', 'Interactive 3D Monthly Spending Analytics');

    this.renderer = new THREE.WebGLRenderer({
      canvas: this.canvas,
      antialias: !isSoftwareGl,
      alpha: true,
      powerPreference: 'high-performance',
    });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, isSoftwareGl ? 1 : 2));
    this.renderer.toneMapping = THREE.ACESFilmicToneMapping;

    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(38, 1.6, 0.1, 40);
    this.camera.position.set(0, 1.3, 4.9);
    this.camera.lookAt(0, 0.45, 0);

    this.pmrem = new THREE.PMREMGenerator(this.renderer);
    const room = new RoomEnvironment();
    this.envRT = this.pmrem.fromScene(room, 0.04);
    room.dispose();
    this.scene.environment = this.envRT.texture;
    this.scene.environmentIntensity = 0.72;

    const key = new THREE.DirectionalLight(0xfaf6ee, 1.65);
    key.position.set(3, 5, 4);
    this.scene.add(key);

    this.group = new THREE.Group();
    this.scene.add(this.group);

    // Subtle reflective base grid plane
    const baseGeo = new THREE.BoxGeometry(4.4, 0.08, 1.3);
    const baseMat = new THREE.MeshStandardMaterial({ color: 0x0d1b35, metalness: 0.65, roughness: 0.35 });
    const base = new THREE.Mesh(baseGeo, baseMat);
    base.position.set(0, -0.04, 0);
    this.group.add(base);

    this.canvas.addEventListener('pointermove', this.onMove, { passive: true });
    this.canvas.addEventListener('pointerleave', this.onLeave, { passive: true });
    this.canvas.addEventListener('webglcontextlost', this.onLost);
    this.resizeObserver = new ResizeObserver(() => this.resize());
  }

  private onMove = (e: PointerEvent) => {
    const r = this.canvas.getBoundingClientRect();
    if (r.width <= 0) return;
    this.pointerX = ((e.clientX - r.left) / r.width - 0.5) * 2;
  };

  private onLeave = () => {
    this.pointerX = 0;
  };

  private onLost = (e: Event) => {
    e.preventDefault();
    this.dispose();
  };

  private rebuildBars(bars: FinanceBarInput[]): void {
    const sig = bars.map((b) => `${b.label}:${b.spent}:${b.limit}`).join('|');
    if (sig === this.lastSig) return;
    this.lastSig = sig;

    while (this.group.children.length > 1) {
      const ch = this.group.children[1];
      this.group.remove(ch);
      if (ch instanceof THREE.Mesh) {
        ch.geometry.dispose();
        const mats = Array.isArray(ch.material) ? ch.material : [ch.material];
        mats.forEach((m) => m.dispose());
      }
    }

    const list = bars.slice(0, 5);
    const maxVal = Math.max(1000, ...list.map((b) => Math.max(b.spent, b.limit)));
    const palette = [0xd4af37, 0x10b981, 0xe7c98f, 0x8b5cf6, 0xc9a96e];
    const spacing = 0.78;
    const startX = -((list.length - 1) * spacing) / 2;

    list.forEach((b, idx) => {
      const x = startX + idx * spacing;
      const h = Math.max(0.18, (b.spent / maxVal) * 2.0);
      const geo = new THREE.BoxGeometry(0.42, h, 0.42);
      const col = b.limit > 0 && b.spent > b.limit ? 0xf87171 : palette[idx % palette.length];
      const mat = new THREE.MeshPhysicalMaterial({
        color: col,
        metalness: 0.72,
        roughness: 0.22,
        clearcoat: 0.65,
      });
      const mesh = new THREE.Mesh(geo, mat);
      mesh.position.set(x, h / 2, 0);
      this.group.add(mesh);

      if (b.limit > 0) {
        const capH = Math.max(0.15, (b.limit / maxVal) * 2.0);
        const wireMat = new THREE.MeshBasicMaterial({
          color: 0xe7c98f,
          wireframe: true,
          transparent: true,
          opacity: 0.28,
        });
        const capMesh = new THREE.Mesh(new THREE.BoxGeometry(0.48, capH, 0.48), wireMat);
        capMesh.position.set(x, capH / 2, 0);
        this.group.add(capMesh);
      }
    });
  }

  attach(host: HTMLElement, input: FinanceVisualInput): void {
    if (this.disposed) return;
    this.rebuildBars(input.bars);
    const capHtml = `<span>${esc(input.caption)}</span><span class="num">${input.bars.length} categories</span>`;
    if (this.attachedHost !== host) {
      if (this.attachedHost) this.resizeObserver?.unobserve(this.attachedHost);
      host.innerHTML = '';
      host.appendChild(this.canvas);
      const caption = document.createElement('div');
      caption.className = 'stage-3d-caption';
      caption.innerHTML = capHtml;
      host.appendChild(caption);
      this.attachedHost = host;
      this.resizeObserver?.observe(host);
    } else {
      const cap = host.querySelector('.stage-3d-caption');
      if (cap) cap.innerHTML = capHtml;
    }
    this.resize();
    if (!this.frameId) {
      this.lastTick = performance.now();
      this.scheduleNext();
    }
  }

  private resize(): void {
    if (!this.attachedHost || this.disposed) return;
    const w = Math.max(220, this.attachedHost.clientWidth || 320);
    const h = Math.max(200, this.attachedHost.clientHeight || 250);
    this.renderer.setSize(w, h, false);
    this.camera.aspect = w / h;
    this.camera.updateProjectionMatrix();
  }

  private scheduleNext(): void {
    if (this.disposed) return;
    this.frameId = afterDraw(this.renderFrame, this.isSoftwareGl);
  }

  private renderFrame = (): void => {
    if (this.disposed) return;
    if (!document.body.contains(this.canvas)) {
      this.frameId = 0;
      return;
    }
    const now = performance.now();
    const dt = Math.min(0.08, Math.max(0.001, (now - this.lastTick) / 1000));
    this.lastTick = now;
    this.elapsed += dt;

    const targetRot = this.pointerX * 0.42 + Math.sin(this.elapsed * 0.55) * 0.16;
    this.group.rotation.y = THREE.MathUtils.damp(this.group.rotation.y, targetRot, 4.5, dt);
    this.renderer.render(this.scene, this.camera);
    this.scheduleNext();
  };

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    if (this.frameId) {
      cancelScheduledDraw(this.frameId, this.isSoftwareGl);
      this.frameId = 0;
    }
    this.resizeObserver?.disconnect();
    this.canvas.removeEventListener('pointermove', this.onMove);
    this.canvas.removeEventListener('pointerleave', this.onLeave);
    this.canvas.removeEventListener('webglcontextlost', this.onLost);
    this.scene.traverse((obj) => {
      if (obj instanceof THREE.Mesh) {
        obj.geometry.dispose();
        const mats = Array.isArray(obj.material) ? obj.material : [obj.material];
        mats.forEach((m) => m.dispose());
      }
    });
    this.envRT.dispose();
    this.pmrem.dispose();
    this.renderer.dispose();
  }
}

let activeShieldCtrl: ShieldController | null = null;
let activeGlobeCtrl: GlobeController | null = null;
let activeOrbCtrl: OrbController | null = null;
let activeFinanceCtrl: FinanceChartController | null = null;

export function syncThreeVisuals(params: {
  shield?: ShieldVisualInput;
  globe?: GlobeVisualInput;
  orb?: OrbVisualInput;
  finance?: FinanceVisualInput;
}): void {
  const shieldEl = document.getElementById('guardian-3d-shield');
  const globeEl = document.getElementById('guardian-3d-globe');
  const orbEl = document.getElementById('guardian-3d-orb');
  const financeEl = document.getElementById('guardian-3d-finance');
  const glProbe = detectWebGl();
  const useFallback = !glProbe.supported || prefersReducedMotion();

  if (shieldEl && params.shield) {
    if (useFallback) {
      if (activeShieldCtrl) {
        activeShieldCtrl.dispose();
        activeShieldCtrl = null;
      }
      renderShieldSvgFallback(shieldEl, params.shield);
    } else {
      if (!activeShieldCtrl) {
        activeShieldCtrl = new ShieldController(glProbe.isSoftwareGl);
      }
      activeShieldCtrl.attach(shieldEl, params.shield);
    }
  } else if (activeShieldCtrl) {
    activeShieldCtrl.dispose();
    activeShieldCtrl = null;
  }

  if (globeEl && params.globe) {
    if (useFallback) {
      if (activeGlobeCtrl) {
        activeGlobeCtrl.dispose();
        activeGlobeCtrl = null;
      }
      renderGlobeSvgFallback(globeEl, params.globe);
    } else {
      if (!activeGlobeCtrl) {
        activeGlobeCtrl = new GlobeController(glProbe.isSoftwareGl);
      }
      activeGlobeCtrl.attach(globeEl, params.globe);
    }
  } else if (activeGlobeCtrl) {
    activeGlobeCtrl.dispose();
    activeGlobeCtrl = null;
  }

  if (orbEl && params.orb) {
    if (useFallback) {
      if (activeOrbCtrl) {
        activeOrbCtrl.dispose();
        activeOrbCtrl = null;
      }
      renderOrbSvgFallback(orbEl, params.orb);
    } else {
      if (!activeOrbCtrl) {
        activeOrbCtrl = new OrbController(glProbe.isSoftwareGl);
      }
      activeOrbCtrl.attach(orbEl, params.orb);
    }
  } else if (activeOrbCtrl) {
    activeOrbCtrl.dispose();
    activeOrbCtrl = null;
  }

  if (financeEl && params.finance) {
    if (useFallback) {
      if (activeFinanceCtrl) {
        activeFinanceCtrl.dispose();
        activeFinanceCtrl = null;
      }
      renderFinanceSvgFallback(financeEl, params.finance);
    } else {
      if (!activeFinanceCtrl) {
        activeFinanceCtrl = new FinanceChartController(glProbe.isSoftwareGl);
      }
      activeFinanceCtrl.attach(financeEl, params.finance);
    }
  } else if (activeFinanceCtrl) {
    activeFinanceCtrl.dispose();
    activeFinanceCtrl = null;
  }
}

export function disposeThreeVisuals(): void {
  if (activeShieldCtrl) {
    activeShieldCtrl.dispose();
    activeShieldCtrl = null;
  }
  if (activeGlobeCtrl) {
    activeGlobeCtrl.dispose();
    activeGlobeCtrl = null;
  }
  if (activeOrbCtrl) {
    activeOrbCtrl.dispose();
    activeOrbCtrl = null;
  }
  if (activeFinanceCtrl) {
    activeFinanceCtrl.dispose();
    activeFinanceCtrl = null;
  }
}
