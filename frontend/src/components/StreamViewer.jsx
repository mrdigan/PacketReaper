import React, { useEffect, useState } from 'react';
import { X, ArrowDown, ArrowUp, RefreshCw, AlertTriangle } from 'lucide-react';
import { GetStreamContent } from '../../wailsjs/go/main/App';

const StreamViewer = ({ session, onClose }) => {
    const [content, setContent] = useState({ inbound: '', outbound: '' });
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        // Lock scroll on mount
        document.body.style.overflow = 'hidden';

        if (session && session.key) {
            loadStream();
        }

        // Unlock on unmount
        return () => {
            document.body.style.overflow = 'unset';
        };
    }, [session]);

    const loadStream = async () => {
        setLoading(true);
        setError(null);
        try {
            const result = await GetStreamContent(session.key);
            setContent({
                inbound: result.inbound || '',
                outbound: result.outbound || ''
            });
        } catch (err) {
            console.error("Failed to load stream:", err);
            setError("Failed to load stream content. " + err);
        } finally {
            setLoading(false);
        }
    };

    if (!session) return null;

    // Interleave content if possible? 
    // For specific protocols like HTTP, request (outbound) usually comes before response (inbound).
    // But since we just have two blobs, let's display them in a split view or tabs.
    // Split view (Top/Bottom or Left/Right) is good.

    return (
        <div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={onClose}
        >
            <div
                className="bg-white dark:bg-gray-800 rounded-lg shadow-2xl w-full max-w-5xl h-[85vh] flex flex-col border border-gray-200 dark:border-gray-700 animate-in fade-in zoom-in-95 duration-200"
                onClick={(e) => e.stopPropagation()}
            >
                {/* Header */}
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                    <div>
                        <h2 className="text-lg font-bold text-gray-900 dark:text-white flex items-center gap-2">
                            <RefreshCw size={18} className="text-blue-500" />
                            TCP/UDP Stream
                        </h2>
                        <p className="text-xs text-gray-500 font-mono mt-1">
                            {session.src_ip}:{session.src_port} ↔ {session.dst_ip}:{session.dst_port} ({session.protocol})
                        </p>
                    </div>
                    <button
                        onClick={onClose}
                        className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-full text-gray-500 dark:text-gray-400 transition-colors"
                    >
                        <X size={20} />
                    </button>
                </div>

                {/* Content */}
                <div className="flex-1 overflow-hidden flex flex-col md:flex-row divide-y md:divide-y-0 md:divide-x divide-gray-200 dark:divide-gray-700">

                    {/* Outbound (Client -> Server) */}
                    <div className="flex-1 flex flex-col min-h-0 bg-blue-50/30 dark:bg-blue-900/10">
                        <div className="px-4 py-2 bg-blue-100/50 dark:bg-blue-900/30 border-b border-blue-200 dark:border-blue-800/50 flex items-center justify-between gap-2">
                            <span className="text-xs font-bold text-blue-700 dark:text-blue-300 uppercase tracking-wider flex items-center gap-2 truncate">
                                <ArrowUp size={14} className="shrink-0" /> <span className="truncate">Outbound ({session.src_ip})</span>
                            </span>
                            <span className="text-xs font-mono text-blue-600 dark:text-blue-400 shrink-0">
                                {content.outbound.length} bytes
                            </span>
                        </div>
                        <div className="flex-1 overflow-auto p-4 font-mono text-xs whitespace-pre-wrap break-all text-gray-800 dark:text-gray-200 selection:bg-blue-200 dark:selection:bg-blue-800">
                            {loading ? (
                                <div className="animate-pulse flex space-x-4">
                                    <div className="flex-1 space-y-2 py-1">
                                        <div className="h-2 bg-blue-200 dark:bg-blue-700 rounded w-3/4"></div>
                                        <div className="h-2 bg-blue-200 dark:bg-blue-700 rounded w-1/2"></div>
                                    </div>
                                </div>
                            ) : content.outbound ? (
                                content.outbound
                            ) : (
                                <span className="text-gray-400 italic">No data sent.</span>
                            )}
                        </div>
                    </div>

                    {/* Inbound (Server -> Client) */}
                    <div className="flex-1 flex flex-col min-h-0 bg-red-50/30 dark:bg-red-900/10">
                        <div className="px-4 py-2 bg-red-100/50 dark:bg-red-900/30 border-b border-red-200 dark:border-red-800/50 flex items-center justify-between gap-2">
                            <span className="text-xs font-bold text-red-700 dark:text-red-300 uppercase tracking-wider flex items-center gap-2 truncate">
                                <ArrowDown size={14} className="shrink-0" /> <span className="truncate">Inbound ({session.dst_ip})</span>
                            </span>
                            <span className="text-xs font-mono text-red-600 dark:text-red-400 shrink-0">
                                {content.inbound.length} bytes
                            </span>
                        </div>
                        <div className="flex-1 overflow-auto p-4 font-mono text-xs whitespace-pre-wrap break-all text-gray-800 dark:text-gray-200 selection:bg-red-200 dark:selection:bg-red-800">
                            {loading ? (
                                <div className="animate-pulse flex space-x-4">
                                    <div className="flex-1 space-y-2 py-1">
                                        <div className="h-2 bg-red-200 dark:bg-red-700 rounded w-3/4"></div>
                                        <div className="h-2 bg-red-200 dark:bg-red-700 rounded w-1/2"></div>
                                    </div>
                                </div>
                            ) : content.inbound ? (
                                content.inbound
                            ) : (
                                <span className="text-gray-400 italic">No data received.</span>
                            )}
                        </div>
                    </div>
                </div>

                {/* Footer */}
                {error && (
                    <div className="px-6 py-3 bg-red-50 dark:bg-red-900/20 border-t border-red-200 dark:border-red-800 text-red-600 dark:text-red-400 text-xs flex items-center gap-2">
                        <AlertTriangle size={14} />
                        {error}
                    </div>
                )}
            </div>
        </div>
    );
};

export default StreamViewer;
