import { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import WhitelistTab from '../components/admin/WhitelistTab';
import FeedbackTab from '../components/admin/FeedbackTab';
import TrustTab from '../components/admin/TrustTab';
import AuditTab from '../components/admin/AuditTab';
import RedTeamTab from '../components/admin/RedTeamTab';
import AdversarialTab from '../components/admin/AdversarialTab';
import UsersTab from '../components/admin/UsersTab';
import HealthTab from '../components/admin/HealthTab';
import RetrainTab from '../components/admin/RetrainTab';
import DataTab from '../components/admin/DataTab';

const TABS = ['whitelist', 'feedback', 'trust', 'audit', 'red team', 'adversarial', 'users', 'health', 'retrain', 'data'];

export default function AdminPanel() {
  const { user } = useAuth();
  const [tab, setTab] = useState('whitelist');

  if (!user || user.role !== 'admin') {
    return (
      <div className="max-w-sm mx-auto mt-20 p-8 text-center">
        <div className="glass-card p-8">
          <h2 className="text-xl font-bold text-red-400">Access Denied</h2>
          <p className="text-gray-400 mt-2">You must be an admin to view this page.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto p-6 space-y-6">
      <h2 className="text-2xl font-bold" style={{ color: 'var(--accent)' }}>Admin Command Center</h2>
      <div className="flex gap-2 flex-wrap">
        {TABS.map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 rounded-lg font-semibold text-sm transition ${
              tab === t ? 'bg-purple-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>
      {tab === 'whitelist'   && <WhitelistTab />}
      {tab === 'feedback'    && <FeedbackTab />}
      {tab === 'trust'       && <TrustTab />}
      {tab === 'audit'       && <AuditTab />}
      {tab === 'red team'    && <RedTeamTab />}
      {tab === 'adversarial' && <AdversarialTab />}
      {tab === 'users'       && <UsersTab />}
      {tab === 'health'      && <HealthTab />}
      {tab === 'retrain'     && <RetrainTab />}
      {tab === 'data'        && <DataTab />}
    </div>
  );
}
