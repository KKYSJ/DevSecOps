// DevSecOps Dashboard - Top Navigation
// Design: Clean Governance Dashboard | Dark top bar with logo + utilities

import { Shield, Settings } from 'lucide-react';

interface SidebarProps {
  activeSection: string;
  onSectionChange: (section: string) => void;
}

export default function Sidebar({ activeSection, onSectionChange }: SidebarProps) {
  const isPipelineActive = ['iac', 'sast', 'sca', 'cross', 'image', 'deploy', 'dast'].includes(activeSection);
  return (
    <header
      className="w-full h-16 flex items-center justify-between px-5 bg-background border-b border-border"
    >
      <div className="flex items-center gap-4">
        {/* Logo */}
        <div className="flex items-center gap-3">
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center"
            style={{ backgroundColor: 'oklch(0.45 0.18 250)' }}
          >
            <Shield size={20} className="text-white" />
          </div>
          <div>
            <div
              className="text-s font-semibold tracking-widest uppercase"
              style={{ color: 'oklch(0.55 0.18 250)', letterSpacing: '0.12em' }}
            >
              DevSecOps
            </div>
            <div className="text-[11px] font-medium" style={{ color: 'oklch(0.52 0.015 250)' }}>
              Security Dashboard
            </div>
          </div>
        </div>

        {/* Main navigation */}
        <nav className="flex items-center gap-2">
          <button
            onClick={() => onSectionChange('iac')}
            className="flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-all duration-150"
            style={{
              backgroundColor: isPipelineActive ? 'oklch(0.45 0.18 250)' : 'transparent',
              color: isPipelineActive ? 'white' : 'oklch(0.55 0.015 250)',
            }}
            onMouseEnter={(e) => {
              if (activeSection === 'isms' || activeSection === 'siem') {
                e.currentTarget.style.backgroundColor = 'oklch(0.20 0.02 250)';
                e.currentTarget.style.color = 'oklch(0.78 0.01 250)';
              }
            }}
            onMouseLeave={(e) => {
              if (activeSection === 'isms' || activeSection === 'siem') {
                e.currentTarget.style.backgroundColor = 'transparent';
                e.currentTarget.style.color = 'oklch(0.55 0.015 250)';
              }
            }}
          >
            <span>파이프라인</span>
          </button>


          <button
            onClick={() => onSectionChange('isms')}
            className="flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-all duration-150"
            style={{
              backgroundColor: activeSection === 'isms' ? 'oklch(0.45 0.18 250)' : 'transparent',
              color: activeSection === 'isms' ? 'white' : 'oklch(0.55 0.015 250)',
            }}
            onMouseEnter={(e) => {
              if (activeSection !== 'isms') {
                e.currentTarget.style.backgroundColor = 'oklch(0.20 0.02 250)';
                e.currentTarget.style.color = 'oklch(0.78 0.01 250)';
              }
            }}
            onMouseLeave={(e) => {
              if (activeSection !== 'isms') {
                e.currentTarget.style.backgroundColor = 'transparent';
                e.currentTarget.style.color = 'oklch(0.55 0.015 250)';
              }
            }}
          >
            <span>ISMS-P</span>
          </button>



          <button
            onClick={() => onSectionChange('aws')}
            className="flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-all duration-150"
            style={{
              backgroundColor: activeSection === 'aws' ? 'oklch(0.45 0.18 250)' : 'transparent',
              color: activeSection === 'aws' ? 'white' : 'oklch(0.55 0.015 250)',
            }}
          >
            <span>AWS</span>
          </button>

          <button
            onClick={() => onSectionChange('siem')}
            className="flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-all duration-150"
            style={{
              backgroundColor: activeSection === 'siem' ? 'oklch(0.45 0.18 250)' : 'transparent',
              color: activeSection === 'siem' ? 'white' : 'oklch(0.55 0.015 250)',
            }}
            onMouseEnter={(e) => {
              if (activeSection !== 'siem') {
                e.currentTarget.style.backgroundColor = 'oklch(0.20 0.02 250)';
                e.currentTarget.style.color = 'oklch(0.78 0.01 250)';
              }
            }}
            onMouseLeave={(e) => {
              if (activeSection !== 'siem') {
                e.currentTarget.style.backgroundColor = 'transparent';
                e.currentTarget.style.color = 'oklch(0.55 0.015 250)';
              }
            }}
          >
            <span>모니터링</span>
          </button>





        </nav>
      </div>

      {/* Right utilities */}
      <div className="flex items-center gap-3">
        <button
          className="flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-all duration-150"
          style={{ color: 'oklch(0.45 0.015 250)' }}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = 'oklch(0.20 0.02 250)';
            e.currentTarget.style.color = 'oklch(0.78 0.01 250)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = 'transparent';
            e.currentTarget.style.color = 'oklch(0.45 0.015 250)';
          }}
          onClick={() => { }}
        >
          <Settings size={16} />
          <span className="hidden sm:inline">설정</span>
        </button>
        <div className="hidden sm:flex flex-col text-[10px] font-mono text-muted-foreground text-right">
          <span
            className="uppercase tracking-wider"
            style={{ color: 'oklch(0.38 0.01 250)' }}
          >
            Version
          </span>
          <span>v2.4.1-stable</span>
        </div>
      </div>
    </header>
  );
}
