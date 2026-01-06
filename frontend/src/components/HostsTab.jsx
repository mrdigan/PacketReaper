import React, { useState, useMemo } from 'react';
import DataTable from './DataTable';
import { Monitor, FileText, Key, Network, Globe, Phone, Layers, Image as ImageIcon } from 'lucide-react';

const HostsTab = ({ result }) => {
    const [selectedHostIP, setSelectedHostIP] = useState(null);
    const [activeDetailTab, setActiveDetailTab] = useState('info');
    const [searchTerm, setSearchTerm] = useState('');

    const hosts = result?.hosts || [];

    // Filter hosts list
    const filteredHosts = useMemo(() => {
        if (!searchTerm) return hosts;
        const lowerTerm = searchTerm.toLowerCase();
        return hosts.filter(h =>
            h.ip.toLowerCase().includes(lowerTerm) ||
            (h.hostname && h.hostname.toLowerCase().includes(lowerTerm)) ||
            (h.os && h.os.toLowerCase().includes(lowerTerm))
        );
    }, [hosts, searchTerm]);

    // Select first host by default if none selected
    useMemo(() => {
        if (!selectedHostIP && filteredHosts.length > 0) {
            setSelectedHostIP(filteredHosts[0].ip);
        }
    }, [filteredHosts, selectedHostIP]);

    const selectedHost = useMemo(() =>
        hosts.find(h => h.ip === selectedHostIP),
        [hosts, selectedHostIP]
    );

    // Filter related data for the selected host
    const relatedFiles = (result?.files || []).filter(f => f.source_ip === selectedHostIP || f.dest_ip === selectedHostIP);
    const relatedImages = (result?.images || []).filter(i => i.source_ip === selectedHostIP);
    const relatedCreds = (result?.credentials || []).filter(c => c.source_ip === selectedHostIP || c.dest_ip === selectedHostIP);
    const relatedSessions = (result?.sessions || []).filter(s => s.src_ip === selectedHostIP || s.dst_ip === selectedHostIP);
    const relatedDNS = (result?.dns_records || []).filter(d => true); // DNS doesn't map easily to a source IP in current struct, might need enhancement later.
    // Actually DNS records are usually queries FROM a host. 
    // Checking dns.Record struct in backend... packet sender IP isn't explicitly in dns.Record yet? 
    // Let's assume for now we might not show DNS here or filter loosely if possible.

    // Voip calls involving this host
    const relatedVoip = (result?.voip_calls || []).filter(v => v.src_ip === selectedHostIP || v.dst_ip === selectedHostIP);

    if (hosts.length === 0) {
        return <div className="p-8 text-center text-gray-500">No hosts found.</div>;
    }

    return (
        <div className="flex h-full gap-4">
            {/* Left Pane: Host List */}
            <div className="w-1/4 min-w-[250px] flex flex-col bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 overflow-hidden">
                <div className="p-3 border-b border-gray-200 dark:border-gray-700">
                    <input
                        type="text"
                        placeholder="Filter Hosts..."
                        className="w-full px-3 py-1.5 text-sm rounded border border-gray-300 dark:border-gray-600 bg-gray-50 dark:bg-gray-700 dark:text-gray-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                    />
                </div>
                <div className="flex-1 overflow-y-auto">
                    {filteredHosts.map(host => (
                        <div
                            key={host.ip}
                            onClick={() => setSelectedHostIP(host.ip)}
                            className={`px-4 py-3 cursor-pointer border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors ${selectedHostIP === host.ip ? 'bg-blue-50 dark:bg-blue-900/20 border-l-4 border-l-blue-500' : 'border-l-4 border-l-transparent'
                                }`}
                        >
                            <div className="flex items-center justify-between">
                                <span className="font-mono font-bold text-sm text-gray-900 dark:text-gray-100">{host.ip}</span>
                                {host.countryISO && <span className="text-xs text-gray-500">{host.countryISO}</span>}
                            </div>
                            {host.hostname && <div className="text-xs text-gray-500 truncate">{host.hostname}</div>}
                            <div className="flex items-center gap-2 mt-1">
                                <div className={`w-2 h-2 rounded-full ${host.packets_sent > 0 ? 'bg-green-500' : 'bg-gray-300'}`}></div>
                                <span className="text-[10px] text-gray-400 uppercase">{host.os !== 'Unknown' ? host.os : 'Unknown OS'}</span>
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Right Pane: Details */}
            <div className="flex-1 flex flex-col bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700 overflow-hidden">
                {selectedHost ? (
                    <>
                        {/* Header */}
                        <div className="p-6 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900">
                            <h2 className="text-2xl font-bold flex items-center gap-3 text-gray-900 dark:text-white">
                                <Monitor className="text-blue-500" />
                                {selectedHost.ip}
                                {selectedHost.hostname && <span className="text-lg font-normal text-gray-500">({selectedHost.hostname})</span>}
                            </h2>
                            <div className="mt-2 flex gap-4 text-sm text-gray-600 dark:text-gray-400">
                                <span>MAC: <span className="font-mono">{selectedHost.mac || 'N/A'}</span></span>
                                <span>OS: <span className="font-semibold">{selectedHost.os}</span></span>
                                <span>Data: {((selectedHost.bytes_sent + selectedHost.bytes_recv) / 1024).toFixed(1)} KB</span>
                            </div>
                        </div>

                        {/* Tabs */}
                        <div className="flex border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900 px-4 gap-1">
                            {[
                                { id: 'info', label: 'Info', icon: Monitor },
                                { id: 'files', label: `Files (${relatedFiles.length})`, icon: FileText },
                                { id: 'creds', label: `Credentials (${relatedCreds.length})`, icon: Key },
                                { id: 'images', label: `Images (${relatedImages.length})`, icon: ImageIcon },
                                { id: 'sessions', label: `Sessions (${relatedSessions.length})`, icon: Network },
                            ].map(tab => (
                                <button
                                    key={tab.id}
                                    onClick={() => setActiveDetailTab(tab.id)}
                                    className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${activeDetailTab === tab.id
                                            ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                                            : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200'
                                        }`}
                                >
                                    <tab.icon size={14} />
                                    {tab.label}
                                </button>
                            ))}
                        </div>

                        {/* Content */}
                        <div className="flex-1 overflow-y-auto p-0 bg-gray-50/50 dark:bg-gray-900/50">
                            {activeDetailTab === 'info' && (
                                <div className="p-6 space-y-6">
                                    <div className="grid grid-cols-2 gap-6">
                                        <div className="bg-white dark:bg-gray-800 p-4 rounded shadow-sm border border-gray-100 dark:border-gray-700">
                                            <h3 className="text-xs font-bold text-gray-500 uppercase mb-3">Location</h3>
                                            <dl className="space-y-2 text-sm">
                                                <div className="flex justify-between">
                                                    <dt className="text-gray-500">Country</dt>
                                                    <dd className="font-medium text-gray-900 dark:text-white">{selectedHost.country || '-'}</dd>
                                                </div>
                                                <div className="flex justify-between">
                                                    <dt className="text-gray-500">City</dt>
                                                    <dd className="font-medium text-gray-900 dark:text-white">{selectedHost.city || '-'}</dd>
                                                </div>
                                                <div className="flex justify-between">
                                                    <dt className="text-gray-500">ASN</dt>
                                                    <dd className="font-medium text-gray-900 dark:text-white">{selectedHost.asn || '-'}</dd>
                                                </div>
                                                <div className="flex justify-between">
                                                    <dt className="text-gray-500">Org</dt>
                                                    <dd className="font-medium text-gray-900 dark:text-white truncate max-w-[200px]" title={selectedHost.organization}>{selectedHost.organization || '-'}</dd>
                                                </div>
                                            </dl>
                                        </div>

                                        <div className="bg-white dark:bg-gray-800 p-4 rounded shadow-sm border border-gray-100 dark:border-gray-700">
                                            <h3 className="text-xs font-bold text-gray-500 uppercase mb-3">Open Ports</h3>
                                            <div className="flex flex-wrap gap-2">
                                                {(selectedHost.open_ports || []).length > 0 ? (
                                                    selectedHost.open_ports.map(port => (
                                                        <span key={port} className="px-2 py-1 bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300 text-xs font-mono rounded">
                                                            {port}
                                                        </span>
                                                    ))
                                                ) : (
                                                    <span className="text-sm text-gray-400 italic">No open ports detected</span>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {activeDetailTab === 'files' && (
                                <div className="p-4">
                                    <DataTable
                                        title=""
                                        data={relatedFiles}
                                        columns={[
                                            { header: 'Filename', accessor: 'filename' },
                                            { header: 'Size', accessor: 'size', render: r => (r.size / 1024).toFixed(1) + ' KB' },
                                            { header: 'Type', accessor: 'extension' },
                                            // Reuse existing renderers if possible, for now simple text
                                        ]}
                                    />
                                </div>
                            )}

                            {activeDetailTab === 'images' && (
                                <div className="p-4 grid grid-cols-4 gap-4">
                                    {relatedImages.map((img, idx) => (
                                        <div key={idx} className="bg-white dark:bg-gray-800 p-2 rounded shadow border border-gray-200 dark:border-gray-700">
                                            <img src={`data:image/png;base64,${img.data}`} alt={img.filename} className="w-full h-32 object-contain bg-gray-100 dark:bg-black rounded" />
                                            <div className="mt-2 text-xs truncate text-center text-gray-500">{img.filename}</div>
                                        </div>
                                    ))}
                                    {relatedImages.length === 0 && <div className="col-span-4 text-center text-gray-500 py-8">No images found for this host.</div>}
                                </div>
                            )}

                            {activeDetailTab === 'creds' && (
                                <div className="p-4">
                                    <DataTable
                                        data={relatedCreds}
                                        columns={[
                                            { header: 'Protocol', accessor: 'protocol' },
                                            { header: 'Username', accessor: 'username' },
                                            { header: 'Password', accessor: 'password' },
                                        ]}
                                    />
                                </div>
                            )}

                            {activeDetailTab === 'sessions' && (
                                <div className="p-4">
                                    <DataTable
                                        data={relatedSessions}
                                        columns={[
                                            { header: 'Protocol', accessor: 'protocol' },
                                            { header: 'Peer', render: s => s.src_ip === selectedHostIP ? `${s.dst_ip}:${s.dst_port}` : `${s.src_ip}:${s.src_port}` },
                                            { header: 'Duration', accessor: 'duration' },
                                            { header: 'Bytes', accessor: 'byte_count' },
                                        ]}
                                    />
                                </div>
                            )}
                        </div>
                    </>
                ) : (
                    <div className="flex-1 flex items-center justify-center text-gray-400">
                        Select a host to view details
                    </div>
                )}
            </div>
        </div>
    );
};

export default HostsTab;
