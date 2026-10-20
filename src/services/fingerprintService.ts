/**
 * Device Fingerprint Service
 * Captures real browser/device fingerprint for anomaly detection.
 * When a different device logs in, this fingerprint automatically differs
 * from the stored baseline — no simulation needed.
 */

export interface DeviceFingerprint {
  userAgent: string;
  platform: string;
  language: string;
  languages: string[];
  timezone: string;
  timezoneOffset: number;
  screenResolution: string;
  colorDepth: number;
  deviceMemory: number | null;
  hardwareConcurrency: number;
  touchSupport: boolean;
  cookiesEnabled: boolean;
  doNotTrack: string | null;
  canvasHash: string;
  webglVendor: string;
  webglRenderer: string;
  deviceType: 'mobile' | 'tablet' | 'desktop';
}

/**
 * Generate a simple hash from a string (for canvas fingerprint)
 */
function simpleHash(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash |= 0; // Convert to 32-bit int
  }
  return Math.abs(hash).toString(16).padStart(8, '0');
}

/**
 * Generate a canvas fingerprint hash.
 * Different GPUs / browsers render text slightly differently,
 * so this changes across devices automatically.
 */
function getCanvasFingerprint(): string {
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 200;
    canvas.height = 50;
    const ctx = canvas.getContext('2d');
    if (!ctx) return 'no-canvas';

    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('TrustNet FP 🔒', 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('TrustNet FP 🔒', 4, 17);

    return simpleHash(canvas.toDataURL());
  } catch {
    return 'canvas-error';
  }
}

/**
 * Get WebGL vendor and renderer — differs across GPUs
 */
function getWebGLInfo(): { vendor: string; renderer: string } {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return { vendor: 'no-webgl', renderer: 'no-webgl' };

    const debugInfo = (gl as WebGLRenderingContext).getExtension('WEBGL_debug_renderer_info');
    if (!debugInfo) return { vendor: 'unknown', renderer: 'unknown' };

    return {
      vendor: (gl as WebGLRenderingContext).getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || 'unknown',
      renderer: (gl as WebGLRenderingContext).getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || 'unknown',
    };
  } catch {
    return { vendor: 'error', renderer: 'error' };
  }
}

/**
 * Detect device type from screen size and touch support
 */
function getDeviceType(): 'mobile' | 'tablet' | 'desktop' {
  const width = window.screen.width;
  const hasTouch = 'ontouchstart' in window || navigator.maxTouchPoints > 0;
  if (hasTouch && width < 768) return 'mobile';
  if (hasTouch && width < 1024) return 'tablet';
  return 'desktop';
}

/**
 * Collect the full device fingerprint.
 * Call this on login — the result is sent to the backend
 * for comparison against the stored baseline.
 */
export function collectFingerprint(): DeviceFingerprint {
  const webgl = getWebGLInfo();

  return {
    userAgent: navigator.userAgent,
    platform: navigator.platform || 'unknown',
    language: navigator.language,
    languages: [...(navigator.languages || [navigator.language])],
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    timezoneOffset: new Date().getTimezoneOffset(),
    screenResolution: `${window.screen.width}x${window.screen.height}`,
    colorDepth: window.screen.colorDepth,
    deviceMemory: (navigator as Navigator & { deviceMemory?: number }).deviceMemory ?? null,
    hardwareConcurrency: navigator.hardwareConcurrency || 1,
    touchSupport: 'ontouchstart' in window || navigator.maxTouchPoints > 0,
    cookiesEnabled: navigator.cookieEnabled,
    doNotTrack: navigator.doNotTrack,
    canvasHash: getCanvasFingerprint(),
    webglVendor: webgl.vendor,
    webglRenderer: webgl.renderer,
    deviceType: getDeviceType(),
  };
}

/**
 * Generate a compact fingerprint ID (hash of key fields).
 * Two identical devices will produce the same ID.
 * A different device will produce a different ID.
 */
export function getFingerprintId(fp: DeviceFingerprint): string {
  const key = [
    fp.userAgent,
    fp.platform,
    fp.screenResolution,
    fp.timezone,
    fp.canvasHash,
    fp.webglRenderer,
    fp.hardwareConcurrency,
    fp.colorDepth,
  ].join('|');
  return simpleHash(key);
}
