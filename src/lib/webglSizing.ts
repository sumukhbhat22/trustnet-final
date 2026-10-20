export interface WebGLBufferSize {
  width: number;
  height: number;
}

/** Compute an aspect-preserving physical render-buffer size from CSS dimensions. */
export function getCanvasBufferSize(
  clientWidth: number,
  clientHeight: number,
  devicePixelRatio = 1,
  quality = 1,
  maxPixels = Number.POSITIVE_INFINITY,
): WebGLBufferSize {
  const cssWidth = Number.isFinite(clientWidth) ? Math.max(1, clientWidth) : 1;
  const cssHeight = Number.isFinite(clientHeight) ? Math.max(1, clientHeight) : 1;
  const dpr = Number.isFinite(devicePixelRatio) ? Math.max(0.1, devicePixelRatio) : 1;
  const scaleQuality = Number.isFinite(quality) ? Math.max(0.1, quality) : 1;
  const pixelLimit = Number.isFinite(maxPixels) ? Math.max(1, maxPixels) : Number.POSITIVE_INFINITY;
  const scale = Math.min(dpr * scaleQuality, Math.sqrt(pixelLimit / (cssWidth * cssHeight)));
  return {
    width: Math.max(1, Math.round(cssWidth * scale)),
    height: Math.max(1, Math.round(cssHeight * scale)),
  };
}
