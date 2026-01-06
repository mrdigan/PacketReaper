import React from 'react';
import Sidebar from './Sidebar';
import Header from './Header';

const Layout = ({ children, activeTab, setActiveTab, filename, toggleTheme, theme, onLoadPcap, keyLoaded }) => {
    return (
        <div className="flex h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100 font-sans overflow-hidden transition-colors duration-200">
            {/* Sidebar (Flex Item - Fixed Width) */}
            <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} keyLoaded={keyLoaded} />

            {/* Main Content Column */}
            <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
                {/* Header (Flex Item) */}
                <Header filename={filename} toggleTheme={toggleTheme} theme={theme} onLoadPcap={onLoadPcap} />

                {/* Content (Flex Item - Growing) */}
                <main className="flex-1 overflow-y-auto p-6 scroll-smooth">
                    <div className="max-w-7xl mx-auto h-full">
                        {children}
                    </div>
                </main>
            </div>
        </div>
    );
};

export default Layout;
