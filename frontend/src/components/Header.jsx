import React from 'react';
import { FolderOpen, Sun, Moon, User, Grid } from 'lucide-react';

const Header = ({ filename, toggleTheme, theme, onLoadPcap }) => {
    return (
        <header className="h-16 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between px-6 z-10 shrink-0 transition-colors duration-200">
            {/* Left: Breadcrumbs / File Info */}
            <div className="flex items-center space-x-4 text-sm">
                <span className="text-gray-500 dark:text-gray-400 font-medium">PCAPS</span>
                <span className="text-gray-300 dark:text-gray-600">/</span>
                <span className="text-gray-900 dark:text-white font-semibold">{filename || "No File Selected"}</span>
            </div>

            {/* Center: Load PCAP Button */}
            <div className="flex-1 max-w-xl mx-8 flex justify-center">
                <button
                    onClick={onLoadPcap}
                    className="flex items-center space-x-2 px-6 py-2 bg-cyan-600 hover:bg-cyan-700 text-white font-semibold rounded-lg shadow transition-all duration-200 hover:shadow-lg"
                >
                    <FolderOpen className="h-5 w-5" />
                    <span>Load PCAP</span>
                </button>
            </div>

            {/* Right: Actions */}
            <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-2 border-r border-gray-200 dark:border-gray-700 pr-4">
                    <button
                        onClick={toggleTheme}
                        className="p-1 text-gray-400 hover:text-gray-500 dark:hover:text-gray-200 focus:outline-none transition-colors"
                    >
                        {theme === 'dark' ? <Moon className="h-5 w-5" /> : <Sun className="h-5 w-5" />}
                    </button>
                </div>
                <button className="p-1 text-gray-400 hover:text-gray-500">
                    <User className="h-5 w-5" />
                </button>
                <button className="p-1 text-gray-400 hover:text-gray-500">
                    <Grid className="h-5 w-5" />
                </button>
            </div>
        </header>
    );
};

export default Header;
