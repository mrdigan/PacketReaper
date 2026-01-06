import React, { useState } from 'react';
import { Lock, Unlock, Key, FileText, CheckCircle, AlertCircle } from 'lucide-react';

const DecryptionTab = ({ result }) => {
    // Filter sessions that have decrypted content
    const decryptedSessions = result?.sessions?.filter(s => s.decrypted_content && s.decrypted_content.length > 0) || [];

    return (
        <div className="h-full flex flex-col gap-6 p-6 overflow-y-auto">
            {/* Decrypted Sessions List */}
            <div className="flex-1 bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 flex flex-col overflow-hidden">
                <div className="p-4 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900/50 flex justify-between items-center">
                    <h3 className="font-semibold text-gray-900 dark:text-gray-100 flex items-center gap-2">
                        <FileText size={18} />
                        Decrypted Sessions
                        <span className="bg-amber-100 text-amber-800 text-xs px-2 py-0.5 rounded-full dark:bg-amber-900/40 dark:text-amber-300">
                            {decryptedSessions.length}
                        </span>
                    </h3>
                    <span className="text-xs text-gray-400 italic">
                        Load key first, then load PCAP to apply decryption.
                    </span>
                </div>

                <div className="flex-1 overflow-auto p-0">
                    {decryptedSessions.length === 0 ? (
                        <div className="h-full flex flex-col items-center justify-center text-gray-400">
                            <Lock size={48} className="mb-4 opacity-20" />
                            <p>No decrypted sessions found.</p>
                            <p className="text-sm mt-2">1. Load Private Key</p>
                            <p className="text-sm">2. Reload PCAP file</p>
                        </div>
                    ) : (
                        <div className="divide-y divide-gray-200 dark:divide-gray-700">
                            {decryptedSessions.map((session, idx) => (
                                <div key={idx} className="p-4 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors">
                                    <div className="flex items-center justify-between mb-2">
                                        <div className="flex items-center gap-2 font-mono text-sm">
                                            <span className="text-blue-600 dark:text-blue-400">{session.src_ip}:{session.src_port}</span>
                                            <span className="text-gray-400">→</span>
                                            <span className="text-red-600 dark:text-red-400">{session.dst_ip}:{session.dst_port}</span>
                                        </div>
                                        <div className="text-xs text-gray-500">
                                            {session.protocol} | {session.byte_count} bytes
                                        </div>
                                    </div>

                                    <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs overflow-x-auto whitespace-pre-wrap max-h-48 border border-gray-700 shadow-inner">
                                        {session.decrypted_content}
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default DecryptionTab;
