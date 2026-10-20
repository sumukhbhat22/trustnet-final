import { useEffect, useState } from "react";
import { ShieldCheck, X } from "lucide-react";
import { mlBackendService } from "@/services/mlBackendService";

export default function MFAChallengeDialog() {
  const [open, setOpen] = useState(false);
  const [code, setCode] = useState("");
  const [demoCode, setDemoCode] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const show = () => { setOpen(true); setMessage("Step-up verification is required to continue."); };
    window.addEventListener("trustnet:mfa-required", show);
    return () => window.removeEventListener("trustnet:mfa-required", show);
  }, []);

  const sendCode = async () => {
    setBusy(true); setMessage("");
    try {
      const result = await mlBackendService.requestMfaChallenge();
      setDemoCode(result.demo_code || "");
      setMessage(result.delivery === "email" ? "A verification code was sent to your account email." : "Local demo code generated. Use it only in this demo environment.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not request a verification code.");
    } finally { setBusy(false); }
  };

  const verify = async () => {
    if (!/^\d{6}$/.test(code)) { setMessage("Enter the six-digit code."); return; }
    setBusy(true); setMessage("");
    try {
      await mlBackendService.verifyMfaCode(code);
      setMessage("Verified. Retry the action you were performing.");
      setCode(""); setDemoCode("");
      window.setTimeout(() => setOpen(false), 1200);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Verification failed.");
    } finally { setBusy(false); }
  };

  if (!open) return null;
  return <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 p-4" role="dialog" aria-modal="true" aria-labelledby="mfa-title">
    <div className="w-full max-w-md rounded-xl border border-primary/40 bg-background p-6 shadow-2xl">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3"><ShieldCheck className="h-6 w-6 text-primary" /><div><h2 id="mfa-title" className="text-lg font-semibold">Step-up verification</h2><p className="text-xs text-muted-foreground">Confirm your session to continue.</p></div></div>
        <button type="button" onClick={() => setOpen(false)} aria-label="Close MFA dialog"><X className="h-4 w-4" /></button>
      </div>
      <button type="button" onClick={() => void sendCode()} disabled={busy} className="mt-5 w-full rounded-md border border-primary/40 px-3 py-2 text-sm disabled:opacity-50">{busy ? "Please wait…" : "Send / generate code"}</button>
      {demoCode && <p className="mt-3 rounded bg-muted p-2 text-sm">Demo code: <strong className="font-mono">{demoCode}</strong></p>}
      <label htmlFor="mfa-code" className="mt-4 block text-xs text-muted-foreground">6-digit verification code</label>
      <input id="mfa-code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, ""))} className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 font-mono tracking-[0.4em]" />
      <button type="button" onClick={() => void verify()} disabled={busy || code.length !== 6} className="mt-3 w-full rounded-md bg-primary px-3 py-2 text-sm text-primary-foreground disabled:opacity-50">Verify</button>
      {message && <p className="mt-3 text-xs text-muted-foreground" role="status">{message}</p>}
    </div>
  </div>;
}
