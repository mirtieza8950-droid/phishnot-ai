import { useState, useEffect } from 'react';
import { retrainModel, triggerSelfLearning, getSelfLearningStatus, triggerMetaRetrain, triggerLoRAFinetune } from '../../api/phishguard';
import { useReveal } from '../../hooks/useReveal';

export default function RetrainTab() {
  const [loading, setLoading] = useState('');
  const [message, setMessage] = useState('');
  const [status, setStatus] = useState(null);
  const ref = useReveal();

  const loadStatus = async () => {
    try {
      const s = await getSelfLearningStatus();
      setStatus(s);
    } catch (e) {
      console.error('Failed to load status', e);
    }
  };

  useEffect(() => { loadStatus(); }, []);

  const runAction = async (action, fn) => {
    setLoading(action);
    setMessage('');
    try {
      await fn();
      setMessage(`${action} started. Check server logs.`);
      loadStatus();
    } catch {
      setMessage(`Failed to trigger ${action}.`);
    } finally {
      setLoading('');
    }
  };

  return (
    <div ref={ref} className="space-y-4">
      {/* Scheduler Status */}
      {status && (
        <div className="glass-card p-6">
          <h3 className="text-lg font-bold text-white mb-4">Self-Learning Scheduler</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
            <ScheduleCard
              title="Weekly Meta-Learner"
              next={status.next_meta_retrain}
              last={status.last_meta_retrain}
              color="text-blue-400"
            />
            <ScheduleCard
              title="Monthly LoRA"
              next={status.next_lora_finetune}
              last={status.last_lora_finetune}
              color="text-purple-400"
            />
            <ScheduleCard
              title="Quarterly Full Retrain"
              next={status.next_full_retrain}
              last={status.last_full_retrain}
              color="text-yellow-400"
            />
          </div>
        </div>
      )}

      {/* Manual Controls */}
      <div className="glass-card p-6 space-y-4">
        <h3 className="text-lg font-bold text-white">Manual Training Controls</h3>

        <ActionCard
          title="Full Self-Learning Pipeline"
          description="Run canary injection, consensus validation, quarantine decisions, and export training data. Fast."
          action="Run Pipeline"
          loading={loading === 'pipeline'}
          onClick={() => runAction('pipeline', triggerSelfLearning)}
        />

        <ActionCard
          title="Retrain Meta-Learner (Fast)"
          description="Retrain XGBoost stacking model on validation data + confirmed feedback. ~2 minutes. Safe to run weekly."
          action="Retrain Meta-Learner"
          loading={loading === 'meta'}
          onClick={() => runAction('meta', triggerMetaRetrain)}
        />

        <ActionCard
          title="LoRA Fine-Tune (Moderate)"
          description="Fine-tune DeBERTa and DistilRoBERTa with low-rank adapters on feedback data. ~30 minutes. Monthly."
          action="Start LoRA Fine-Tune"
          loading={loading === 'lora'}
          onClick={() => runAction('lora', triggerLoRAFinetune)}
          warning
        />

        <ActionCard
          title="Full Retrain (Hours)"
          description="Retrain all 4 base models from scratch. ~4 hours total. Only run quarterly or when accuracy degrades significantly."
          action="Start Full Retrain"
          loading={loading === 'full'}
          onClick={() => runAction('full', retrainModel)}
          danger
        />

        {message && <p className="text-sm text-purple-400">{message}</p>}
      </div>
    </div>
  );
}

function ScheduleCard({ title, next, last, color }) {
  return (
    <div className="bg-black/20 p-3 rounded-lg">
      <div className={`font-bold text-sm ${color}`}>{title}</div>
      <div className="text-gray-400 text-xs mt-1">
        Next: <span className="text-gray-300">{next || 'N/A'}</span>
      </div>
      <div className="text-gray-500 text-xs">
        Last: <span className="text-gray-400">{last || 'Never'}</span>
      </div>
    </div>
  );
}

function ActionCard({ title, description, action, loading, onClick, warning, danger }) {
  return (
    <div className="bg-black/20 p-4 rounded-lg flex items-center justify-between">
      <div className="flex-1 mr-4">
        <div className="font-bold text-sm text-white">{title}</div>
        <div className="text-gray-400 text-xs mt-0.5">{description}</div>
      </div>
      <button
        onClick={onClick}
        disabled={loading}
        className={`px-5 py-2.5 font-bold rounded-lg text-sm whitespace-nowrap disabled:opacity-50 ${
          danger ? 'bg-red-600 text-white hover:bg-red-500' :
          warning ? 'bg-yellow-600 text-white hover:bg-yellow-500' :
          'bg-green-600 text-white hover:bg-green-500'
        }`}
      >
        {loading ? 'Running...' : action}
      </button>
    </div>
  );
}
