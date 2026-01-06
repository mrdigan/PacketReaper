import React, { useState } from 'react';
import { Activity, AlertTriangle, Monitor, FileText, Layers, Key, Image, Network, List, Mail, Shield, Search, Globe, Phone, ChevronDown, ChevronRight, LayoutDashboard, Unlock } from 'lucide-react';
import logo from '../assets/images/logo.png';

const Sidebar = ({ activeTab, setActiveTab, keyLoaded }) => {
    // State for collapsible groups
    const [groups, setGroups] = useState({
        analysis: true, // Specific Analysis tools open by default
        artifacts: true // Extracted data open by default
    });

    const toggleGroup = (group) => {
        setGroups(prev => ({ ...prev, [group]: !prev[group] }));
    };

    const mainItems = [
        { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
        { id: 'hosts', label: 'Hosts', icon: Network },
    ];

    const artifactItems = [
        { id: 'files', label: 'Files', icon: FileText },
        { id: 'images', label: 'Images', icon: Image },
        { id: 'credentials', label: 'Credentials', icon: Key },
        { id: 'certificates', label: 'Certificates', icon: Shield },
        { id: 'messages', label: 'Messages (Email)', icon: Mail },
    ];

    const analysisItems = [
        { id: 'sessions', label: 'Sessions', icon: Activity },
        { id: 'dns', label: 'DNS Records', icon: Layers },
        { id: 'keywords', label: 'Keywords', icon: Search },
        { id: 'browsers', label: 'Browsers', icon: Globe },
        { id: 'map', label: 'GeoIP Map', icon: Globe },
        { id: 'voip', label: 'VoIP', icon: Phone },
        { id: 'anomalies', label: 'Anomalies', icon: AlertTriangle },
        { id: 'decryption', label: 'Decryption', icon: Unlock },
        { id: 'parameters', label: 'Parameters', icon: FileText },
    ];

    const renderItem = (item) => (
        <button
            key={item.id}
            onClick={() => setActiveTab(item.id)}
            className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg transition-colors duration-200 ${activeTab === item.id
                ? 'bg-blue-600 text-white shadow-lg shadow-blue-900/20'
                : 'text-gray-400 hover:text-white hover:bg-gray-800'
                }`}
        >
            <item.icon size={18} />
            <span className="font-medium text-sm">{item.label}</span>
        </button>
    );

    return (
        <div className="w-64 h-full bg-gray-900 flex flex-col border-r border-gray-800">
            {/* Logo area */}
            <div className="p-6 flex items-center space-x-3 border-b border-gray-800">
                <img src={logo} alt="Logo" className="w-8 h-8" />
                <span className="text-xl font-bold bg-gradient-to-r from-blue-400 to-teal-400 bg-clip-text text-transparent">
                    PACKETREAPER
                </span>
            </div>

            {/* Navigation Items */}
            <div className="flex-1 px-4 py-6 space-y-2 overflow-y-auto custom-scrollbar">

                {/* Main Section */}
                {mainItems.map(renderItem)}

                <div className="pt-4 pb-2">
                    <div className="h-px bg-gray-800 mx-2"></div>
                </div>

                {/* Artifacts Group */}
                <div className="space-y-1">
                    <button
                        onClick={() => toggleGroup('artifacts')}
                        className="w-full flex items-center justify-between px-2 py-2 text-xs font-bold text-gray-500 uppercase tracking-wider hover:text-gray-300"
                    >
                        <span>Extracted Artifacts</span>
                        {groups.artifacts ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    </button>

                    {groups.artifacts && (
                        <div className="space-y-1 pl-2 border-l border-gray-800 ml-2">
                            {artifactItems.map(renderItem)}
                        </div>
                    )}
                </div>

                <div className="pt-4 pb-2">
                    <div className="h-px bg-gray-800 mx-2"></div>
                </div>

                {/* Analysis Group */}
                <div className="space-y-1">
                    <button
                        onClick={() => toggleGroup('analysis')}
                        className="w-full flex items-center justify-between px-2 py-2 text-xs font-bold text-gray-500 uppercase tracking-wider hover:text-gray-300"
                    >
                        <span>Network Analysis</span>
                        {groups.analysis ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    </button>

                    {groups.analysis && (
                        <div className="space-y-1 pl-2 border-l border-gray-800 ml-2">
                            {analysisItems.filter(item => item.id !== 'decryption' || keyLoaded).map(renderItem)}
                        </div>
                    )}
                </div>

            </div>

            {/* User Profile / Status */}
            <div className="p-4 border-t border-gray-800">
                <div className="flex items-center space-x-3 px-2">
                    <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-blue-500 to-teal-500 flex items-center justify-center text-white font-bold text-xs">
                        OP
                    </div>
                    <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-white truncate">Operator</p>
                        <p className="text-xs text-gray-500 truncate">Active Session</p>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Sidebar;
