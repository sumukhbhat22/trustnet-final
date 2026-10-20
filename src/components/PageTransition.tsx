import { motion, type Variants } from "framer-motion";
import type { ReactNode } from "react";

const contentVariants: Variants = {
  initial: { opacity: 0, y: 24, filter: "blur(8px)" },
  animate: {
    opacity: 1,
    y: 0,
    filter: "blur(0px)",
    transition: { duration: 0.55, ease: [0.22, 1, 0.36, 1], delay: 0.08 },
  },
  exit: {
    opacity: 0,
    y: -16,
    filter: "blur(6px)",
    transition: { duration: 0.28, ease: [0.4, 0, 1, 1] },
  },
};

const flashVariants: Variants = {
  initial: { scaleX: 0, opacity: 0.9 },
  animate: {
    scaleX: [0, 1, 1, 0],
    opacity: [0.9, 0.9, 0.9, 0],
    transition: { duration: 0.6, times: [0, 0.35, 0.75, 1], ease: "easeInOut" },
  },
  exit: { opacity: 0, transition: { duration: 0.1 } },
};

export default function PageTransition({ children }: { children: ReactNode }) {
  return (
    <>
      <motion.div
        aria-hidden="true"
        variants={flashVariants}
        initial="initial"
        animate="animate"
        exit="exit"
        style={{
          position: "fixed",
          inset: 0,
          zIndex: 999,
          pointerEvents: "none",
          transformOrigin: "left",
          background:
            "linear-gradient(90deg, transparent, hsl(var(--primary) / 0.14) 45%, hsl(var(--primary) / 0.22) 50%, hsl(var(--primary) / 0.14) 55%, transparent)",
        }}
      />
      <motion.div
        variants={contentVariants}
        initial="initial"
        animate="animate"
        exit="exit"
        style={{ minHeight: "100vh" }}
      >
        {children}
      </motion.div>
    </>
  );
}
