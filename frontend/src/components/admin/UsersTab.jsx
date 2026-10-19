import { useState, useEffect } from 'react';
import { getUsers, setUserRole, setUserStatus } from '../../api/phishguard';
import { useReveal } from '../../hooks/useReveal';

export default function UsersTab() {
  const [users, setUsers] = useState([]);
  const ref = useReveal();

  const load = async () => {
    try { const res = await getUsers(); setUsers(res.users || []); } catch { /* ignore */ }
  };
  useEffect(() => { load(); }, []);

  const handleRole = async (u) => {
    const next = u.role === 'admin' ? 'end_user' : 'admin';
    if (!confirm(`Change ${u.name} to ${next}?`)) return;
    try { await setUserRole(u.id, next); load(); } catch (e) { alert(e.message); }
  };

  const handleStatus = async (u) => {
    const action = u.disabled ? 'enable' : 'disable';
    if (!confirm(`${action} ${u.name}?`)) return;
    try { await setUserStatus(u.id, !u.disabled); load(); } catch (e) { alert(e.message); }
  };

  return (
    <div ref={ref} className="glass-card p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-bold text-white">User Management</h3>
        <button onClick={load} className="text-xs text-gray-400 hover:text-white px-3 py-1.5 bg-gray-800 rounded-lg">Refresh</button>
      </div>
      <p className="text-xs text-gray-500">First registered user is automatically admin. Disable blocks login; demote removes admin access.</p>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-gray-500 text-xs border-b border-gray-700">
              <th className="py-2 text-left pr-4">Name</th>
              <th className="py-2 text-left pr-4">Email</th>
              <th className="py-2 text-left pr-4">Provider</th>
              <th className="py-2 text-left pr-4">Role</th>
              <th className="py-2 text-left pr-4">Status</th>
              <th className="py-2 text-left pr-4">Joined</th>
              <th className="py-2 text-left">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map(u => (
              <tr key={u.id} className="border-b border-gray-800 hover:bg-white/5">
                <td className="py-2 pr-4 text-white font-medium">{u.name}</td>
                <td className="py-2 pr-4 text-gray-400 text-xs">{u.email}</td>
                <td className="py-2 pr-4">
                  <span className="text-xs bg-gray-800 text-gray-300 px-2 py-0.5 rounded">{u.provider}</span>
                </td>
                <td className="py-2 pr-4">
                  <span className={`text-xs font-bold px-2 py-0.5 rounded ${
                    u.role === 'admin' ? 'bg-purple-900 text-purple-300' : 'bg-gray-800 text-gray-400'
                  }`}>{u.role}</span>
                </td>
                <td className="py-2 pr-4">
                  <span className={`text-xs font-semibold ${u.disabled ? 'text-red-400' : 'text-green-400'}`}>
                    {u.disabled ? 'disabled' : 'active'}
                  </span>
                </td>
                <td className="py-2 pr-4 text-xs text-gray-600">
                  {u.created_at ? u.created_at.slice(0, 10) : '—'}
                </td>
                <td className="py-2">
                  <div className="flex gap-2">
                    <button onClick={() => handleRole(u)}
                      className="text-xs px-2 py-1 bg-indigo-800 hover:bg-indigo-700 text-white rounded">
                      {u.role === 'admin' ? 'Demote' : 'Promote'}
                    </button>
                    <button onClick={() => handleStatus(u)}
                      className={`text-xs px-2 py-1 rounded text-white ${
                        u.disabled ? 'bg-green-800 hover:bg-green-700' : 'bg-red-900 hover:bg-red-800'
                      }`}>
                      {u.disabled ? 'Enable' : 'Disable'}
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {users.length === 0 && (
              <tr><td colSpan={7} className="py-4 text-gray-500 text-center text-sm">No users yet (OAuth login required)</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
