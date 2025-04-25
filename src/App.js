import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import AuthComponent from './components/Auth';
import Dashboard from './components/Dashboard';

export default function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<AuthComponent />} />
        <Route path="/dashboard" element={<Dashboard />} />
      </Routes>
    </Router>
  );
}
