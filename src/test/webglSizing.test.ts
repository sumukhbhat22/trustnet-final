import { describe, expect, it } from "vitest";
import { getCanvasBufferSize } from "@/lib/webglSizing";

describe("getCanvasBufferSize", () => {
  it("keeps the physical buffer aspect ratio aligned with the CSS canvas", () => {
    const clientWidth = 1440;
    const clientHeight = 810;
    const buffer = getCanvasBufferSize(clientWidth, clientHeight, 1.5);

    expect(buffer.width).toBe(2160);
    expect(buffer.height).toBe(1215);
    expect(buffer.width / buffer.height).toBeCloseTo(clientWidth / clientHeight, 6);
  });
});
