import { useEffect, useState } from 'react';
import { mlBackendService, type ProtectedAsset } from '@/services/mlBackendService';

/** F-28: admin editor for protected-asset criticality (1-5). The backend validates and persists the value. */
const AssetCriticalityEditor = ({ canEdit }: { canEdit: boolean }) => {
  const [assets, setAssets] = useState<ProtectedAsset[]>([]);
  const [message, setMessage] = useState('');
  const [error, setError] = useState(false);
  const [savingId, setSavingId] = useState<string | null>(null);

  useEffect(() => {
    mlBackendService.listAssets()
      .then((result) => setAssets(result.assets))
      .catch((e: unknown) => { setError(true); setMessage(e instanceof Error ? e.message : 'Could not load assets.'); });
  }, []);

  const save = async (asset: ProtectedAsset, value: number) => {
    setSavingId(asset.asset_id);
    try {
      const result = await mlBackendService.setAssetCriticality(asset.asset_id, value);
      setAssets((current) => current.map((a) => (a.asset_id === asset.asset_id ? { ...a, criticality: result.criticality } : a)));
      setError(false);
      setMessage(result.changed ? `${asset.label}: criticality ${result.previous} -> ${result.criticality} saved.` : `${asset.label}: unchanged.`);
    } catch (e) {
      setError(true);
      setMessage(e instanceof Error ? e.message : 'Save failed.');
    } finally {
      setSavingId(null);
    }
  };

  return (
    <section aria-label="Asset criticality" className="rounded-lg border border-border p-4 space-y-3">
      <div className="text-xs font-mono text-muted-foreground">ASSET CRITICALITY (1 = low, 5 = crown jewel)</div>
      {!canEdit && <div className="text-xs text-muted-foreground">Read-only: only administrators can change criticality.</div>}
      {assets.map((asset) => (
        <div key={asset.asset_id} className="flex items-center justify-between gap-3 text-sm">
          <span>{asset.label} <span className="text-xs text-muted-foreground">({asset.classification})</span></span>
          <select
            aria-label={`Criticality for ${asset.label}`}
            value={asset.criticality}
            disabled={!canEdit || savingId === asset.asset_id}
            onChange={(event) => void save(asset, Number(event.target.value))}
            className="rounded border border-border bg-background px-2 py-1"
          >
            {[1, 2, 3, 4, 5].map((level) => <option key={level} value={level}>{level}</option>)}
          </select>
        </div>
      ))}
      {!assets.length && !message && <div className="text-xs text-muted-foreground">No protected assets loaded.</div>}
      {message && <div role="status" className="text-xs" style={{ color: error ? 'hsl(var(--threat-critical))' : 'hsl(var(--threat-safe))' }}>{message}</div>}
    </section>
  );
};

export default AssetCriticalityEditor;
