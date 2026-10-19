export default function Login() {
  return (
    <div className="max-w-sm mx-auto mt-20 p-8">
      <div className="glass-card p-8 space-y-6 text-center">
        <h2 className="text-2xl font-bold text-white">Sign In</h2>
        <p className="text-gray-400 text-sm">Use your organization account</p>
        <a href="http://localhost:8000/api/v1/auth/login/google" className="block w-full py-3 bg-white text-gray-900 font-bold rounded-xl hover:bg-gray-100 transition flex items-center justify-center gap-2">
          Sign in with Google
        </a>
        <a href="http://localhost:8000/api/v1/auth/login/microsoft" className="block w-full py-3 bg-white text-gray-900 font-bold rounded-xl hover:bg-gray-100 transition flex items-center justify-center gap-2">
          Sign in with Microsoft
        </a>
      </div>
    </div>
  );
}