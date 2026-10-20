/**
 * Compatibility entry point for the former demo analytics page.
 * Keep every route that imports this module on the persisted-event analytics
 * implementation so synthetic chart data cannot be mistaken for live telemetry.
 */
export { default } from "@/pages/BehaviorAnalyticsPage";
