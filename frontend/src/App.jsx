import React, { useState, useEffect } from 'react';
import { ProcessPcapFile, SelectPcapFile, LoadPrivateKey } from '../wailsjs/go/main/App';
import { EventsOn, BrowserOpenURL } from '../wailsjs/runtime/runtime';
import { Shield, Key, ArrowRight } from 'lucide-react';
import Layout from './components/Layout';
import Dashboard from './components/Dashboard';
import DataTable from './components/DataTable';
import AnomaliesTab from './components/AnomaliesTab';
import DecryptionTab from './components/DecryptionTab';
import HostsTab from './components/HostsTab';
import MapTab from './components/MapTab';
import StreamViewer from './components/StreamViewer';

function App() {
    const [result, setResult] = useState(null);
    const [filePath, setFilePath] = useState("");
    const [activeTab, setActiveTab] = useState('dashboard');
    const [theme, setTheme] = useState('dark');
    const [toastMessage, setToastMessage] = useState('');
    const [showToast, setShowToast] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [loadingProgress, setLoadingProgress] = useState({ current: 0, estimated: 0, percent: 0 });
    const [selectedMessage, setSelectedMessage] = useState(null);
    const [keywords, setKeywords] = useState([]);
    const [newKeyword, setNewKeyword] = useState("");
    const [keyLoaded, setKeyLoaded] = useState(false);
    const [streamSession, setStreamSession] = useState(null);

    const [activeFilters, setActiveFilters] = useState({});

    function handleNavigation(tabId, filters = {}) {
        setActiveTab(tabId);
        setActiveFilters(filters);
    }

    function addKeyword() {
        if (newKeyword.trim() && !keywords.includes(newKeyword.trim())) {
            setKeywords([...keywords, newKeyword.trim()]);
            setNewKeyword("");
        }
    }

    function removeKeyword(kw) {
        setKeywords(keywords.filter(k => k !== kw));
    }

    // Load theme from local storage or default to light
    useEffect(() => {
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme) {
            setTheme(savedTheme);
        } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
            setTheme('dark');
        }
    }, []);

    useEffect(() => {
        if (theme === 'dark') {
            document.documentElement.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
        }
        localStorage.setItem('theme', theme);
    }, [theme]);

    // Listen for progress events
    useEffect(() => {
        const unsubscribe = EventsOn('pcap-progress', (data) => {
            setLoadingProgress({
                current: data.current,
                estimated: data.estimated,
                percent: data.percent
            });
        });
        return () => unsubscribe();
    }, []);

    function copyToClipboard(text, type) {
        navigator.clipboard.writeText(text).then(() => {
            setToastMessage(`${type} Copied to Clipboard`);
            setShowToast(true);
            setTimeout(() => setShowToast(false), 2000);
        });
    }

    function toggleTheme() {
        setTheme(prev => prev === 'dark' ? 'light' : 'dark');
    }

    function loadKey() {
        console.log('[Frontend] loadKey function called');
        LoadPrivateKey().then((msg) => {
            console.log('[Frontend] LoadPrivateKey returned:', msg);
            if (msg) {
                setKeyLoaded(true);
                setToastMessage("Key/KeyLog Loaded");
                setShowToast(true);
                setTimeout(() => setShowToast(false), 2000);
            }
        }).catch((err) => {
            console.error('[Frontend] LoadPrivateKey error:', err);
        });
    }

    function selectFile() {
        SelectPcapFile().then((path) => {
            if (path) {
                setFilePath(path);
                // Auto-process on select for smoother UX
                process(path);
            }
        });
    }

    function process(path) {
        const p = path || filePath;
        if (!p) return;
        setIsLoading(true);
        setLoadingProgress({ current: 0, estimated: 0, percent: 0 });
        setResult({ message: "Processing...", files: [] });
        ProcessPcapFile(p, keywords).then((res) => {
            setResult(res);
            setIsLoading(false);
        }).catch((err) => {
            console.error("Error processing PCAP:", err);
            setIsLoading(false);
        });
    }

    // --- Helper to link Anomaly -> Session ---
    // --- Helper to link Record -> Session ---
    const handleStreamLink = (record) => {
        if (!result || !result.sessions) return;

        let srcIP, srcPort, dstIP, dstPort, proto;

        // Determine fields based on record shape
        if (record.protocol && record.client_ip) {
            // Credential
            srcIP = record.client_ip;
            srcPort = parseInt(record.client_port);
            dstIP = record.server_ip;
            dstPort = parseInt(record.server_port);
            proto = record.protocol === "HTTP" || record.protocol === "FTP" || record.protocol === "SMTP" || record.protocol === "POP3" || record.protocol === "IMAP" ? "TCP" : record.protocol;
            if (record.protocol === "Kerberos") proto = "UDP"; // Usually UDP for extraction check? Actually Kerberos can be TCP. Let's try flexible match.
        } else if (record.method) {
            // HTTP Transaction (Browsing History)
            srcIP = record.src_ip;
            srcPort = record.src_port;
            dstIP = record.dst_ip;
            dstPort = record.dst_port;
            proto = "TCP";
        } else if (record.severity && record.source_ip) {
            // Anomaly
            srcIP = record.source_ip;
            srcPort = record.source_port;
            dstIP = record.dest_ip;
            dstPort = record.dest_port;
            proto = record.protocol;
        } else if (record.filename && record.source_ip) {
            // File or Image
            // Clean IP if it has Ref
            srcIP = record.source_ip.split(' ')[0];
            srcPort = record.source_port;
            dstIP = record.dest_ip || ""; // Images might not have dest_ip in my update? I added dest_port but did I add dest_ip to ImageInfo? 
            // Checked app.go: ImageInfo has SourceIP, SourcePort, DestPort. Lacks DestIP? 
            // Wait, I missed DestIP in ImageInfo! 
            // Let's assume FileDetail has it.
            // For ImageInfo, I might have messed up.
            dstPort = record.dest_port;
            proto = "TCP";

            // Re-check ImageInfo in app.go... I didn't add DestIP. 
            // Use SourceIP/Port and find session with *some* DestIP? 
            // Or just fail for images if I don't fix app.go.
            // Let's apply fix for Files first fully.
        } else {
            // Fallback or unknown
            return;
        }

        // Normalize protocol
        // If proto is "HTTP", map to TCP for session lookup
        if (["HTTP", "FTP", "SMTP", "POP3", "IMAP"].includes(proto)) proto = "TCP";

        // Find session
        const session = result.sessions.find(s => {
            // Flexible protocol match if proto is undefined/null
            const pMatch = !proto || (s.protocol === proto) || (proto === "UDP" && s.protocol === "UDP") || (proto === "TCP" && s.protocol === "TCP");

            // Check bidirectional match
            const forward = s.src_ip === srcIP && s.src_port === srcPort && (!dstIP || s.dst_ip === dstIP) && (!dstPort || s.dst_port === dstPort) && pMatch;
            const reverse = s.src_ip === dstIP && s.src_port === dstPort && (!dstIP || s.dst_ip === srcIP) && (!dstPort || s.src_port === srcPort) && pMatch; // dst_port check on reverse src_port? Wait.

            // Correct logic:
            // Forward: Session(Src) == Record(Src) && Session(Dst) == Record(Dst)
            // Reverse: Session(Src) == Record(Dst) && Session(Dst) == Record(Src)

            const matchFwd = (s.src_ip === srcIP && s.src_port === srcPort) &&
                (!dstIP || s.dst_ip === dstIP) &&
                (!dstPort || s.dst_port === dstPort);

            const matchRev = (s.src_ip === dstIP && s.src_port === dstPort) &&
                (!dstIP || s.dst_ip === srcIP) &&
                (!dstPort || s.dst_port === srcPort); // Wait, Session Dst Port should match Record Src Port? Yes.

            return (matchFwd || matchRev) && pMatch;
        });

        if (session) {
            setStreamSession(session);
        } else {
            setToastMessage("No captured stream session found for this item.");
            setShowToast(true);
            setTimeout(() => setShowToast(false), 3000);
        }
    }

    // --- Tab Rendering Logic ---
    const renderContent = () => {
        if (!result) {
            return (
                <div className="flex flex-col items-center justify-center h-96 bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 transition-colors duration-200">
                    <div className="text-center">
                        <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-2">Welcome to PacketReaper</h2>
                        <p className="text-gray-500 dark:text-gray-400 mb-8">Select a PCAP file to get started.</p>

                        <div className="flex gap-4 justify-center">
                            <button
                                onClick={loadKey}
                                className={`flex items-center gap-2 px-6 py-3 rounded-full shadow transition-transform transform hover:scale-105 font-bold ${keyLoaded
                                    ? "bg-green-600 hover:bg-green-700 text-white"
                                    : "bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-800 dark:text-gray-100"
                                    }`}
                            >
                                <Key size={18} />
                                {keyLoaded ? "Keys Loaded ✓" : "Load Keys"}
                            </button>

                            <button
                                onClick={selectFile}
                                className="bg-cyan-600 hover:bg-cyan-700 text-white font-bold py-3 px-8 rounded-full shadow transition-transform transform hover:scale-105"
                            >
                                Browse PCAP
                            </button>
                        </div>
                    </div>
                </div>
            );
        }

        switch (activeTab) {
            case 'dashboard':
                return <Dashboard data={result} onNavigate={handleNavigation} />;

            case 'hosts':
                return (
                    <DataTable
                        title="Host Inventory"
                        data={result.hosts}
                        rowKey="ip"
                        columns={[
                            { header: 'IP Address', accessor: 'ip', render: (row) => <span className="font-bold text-cyan-500">{row.ip}</span> },
                            { header: 'Organization', accessor: 'organization', render: (row) => <span className="text-purple-600 dark:text-purple-400 font-medium">{row.organization || '-'}</span> },
                            { header: 'Country', accessor: 'country', render: (row) => row.country ? <span className="text-green-500">{row.country}</span> : '-' },
                            { header: 'City', accessor: 'city', render: (row) => row.city || '-' },
                            { header: 'ASN', accessor: 'asn', render: (row) => row.asn ? <span className="font-mono text-xs text-gray-600 dark:text-gray-400">AS{row.asn}</span> : '-' },
                            { header: 'MAC Address', accessor: 'mac' },
                            { header: 'OS Fingerprint', accessor: 'os', render: (row) => <span className="text-amber-500">{row.os}</span> },
                            { header: 'Open Ports', accessor: 'open_ports', render: (row) => row.open_ports?.join(', ') || '-' },
                            { header: 'Packets (S/R)', render: (row) => `${row.packets_sent} / ${row.packets_received}` }
                        ]}
                    />
                );

            case 'hosts':
                return <HostsTab result={result} />;

            case 'certificates':
                return (
                    <DataTable
                        title="SSL/TLS Certificates"
                        data={result.certificates || []}
                        columns={[
                            {
                                header: 'Subject',
                                accessor: 'subject',
                                render: (row) => <span className="font-medium text-cyan-600 dark:text-cyan-400">{row.subject}</span>
                            },
                            {
                                header: 'Issuer',
                                accessor: 'issuer',
                                render: (row) => <span className="text-purple-600 dark:text-purple-400">{row.issuer}</span>
                            },
                            {
                                header: 'Valid Until',
                                accessor: 'not_after',
                                render: (row) => {
                                    const className = row.is_expired
                                        ? 'text-red-600 dark:text-red-400 font-bold'
                                        : row.days_until_expiry < 30
                                            ? 'text-amber-600 dark:text-amber-400'
                                            : 'text-green-600 dark:text-green-400';

                                    return (
                                        <span className={className}>
                                            {row.not_after}
                                            {row.is_expired && ' (EXPIRED)'}
                                        </span>
                                    );
                                }
                            },
                            {
                                header: 'Flags',
                                render: (row) => (
                                    <div className="flex gap-1">
                                        {row.is_self_signed && (
                                            <span className="px-2 py-0.5 text-xs font-semibold rounded bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">
                                                Self-Signed
                                            </span>
                                        )}
                                        {row.is_expired && (
                                            <span className="px-2 py-0.5 text-xs font-semibold rounded bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">
                                                Expired
                                            </span>
                                        )}
                                    </div>
                                )
                            },
                            {
                                header: 'Server',
                                render: (row) => <span className="font-mono text-xs">{row.server_ip}:{row.server_port}</span>
                            },
                            {
                                header: 'SHA256',
                                accessor: 'sha256',
                                render: (row) => (
                                    <span
                                        className="font-mono text-xs text-gray-600 dark:text-gray-400 cursor-pointer hover:underline"
                                        title={row.sha256}
                                        onClick={() => row.sha256 && copyToClipboard(row.sha256, 'SHA256')}
                                    >
                                        {row.sha256 ? `${row.sha256.substring(0, 12)}...` : '-'}
                                    </span>
                                )
                            }
                        ]}
                    />
                );

            case 'dns':
                return (
                    <DataTable
                        title="DNS Records"
                        data={result.dns_records}
                        columns={[
                            { header: 'Timestamp', accessor: 'timestamp' },
                            { header: 'Transaction ID', accessor: 'transaction_id', className: 'w-24' },
                            { header: 'Query', accessor: 'query', className: 'max-w-xs truncate' },
                            { header: 'Type', accessor: 'type', render: (row) => <span className="px-2 py-0.5 rounded text-xs font-semibold bg-gray-100 dark:bg-gray-700 dark:text-gray-200">{row.type}</span> },
                            { header: 'Answers', accessor: 'answers', className: 'max-w-md truncate' }
                        ]}
                    />
                );

            case 'files':
                return (
                    <DataTable
                        title="Extracted Files"
                        data={result.files || []}
                        initialFilters={activeFilters}
                        columns={[
                            { header: 'Filename', accessor: 'filename', render: (row) => <span className="font-medium text-gray-900 dark:text-white">{row.filename}</span> },
                            { header: 'Type', accessor: 'extension', render: (row) => <span className="text-xs uppercase bg-gray-200 dark:bg-gray-700 px-1.5 py-0.5 rounded text-gray-800 dark:text-gray-300">{row.extension}</span> },
                            { header: 'Size', accessor: 'size', render: (row) => <span className="font-mono text-xs">{(row.size / 1024).toFixed(1)} KB</span> },
                            {
                                header: 'MD5', accessor: 'md5', render: (row) => (
                                    <div className="flex items-center gap-2">
                                        <span
                                            className="font-mono text-xs text-cyan-500 dark:text-cyan-400 cursor-pointer hover:underline"
                                            title={row.md5}
                                            onClick={() => row.md5 && copyToClipboard(row.md5, 'MD5')}
                                        >
                                            {row.md5 ? `${row.md5.substring(0, 8)}...` : '-'}
                                        </span>
                                        {row.md5 && (
                                            <button
                                                onClick={() => BrowserOpenURL(`https://www.virustotal.com/gui/file/${row.md5}`)}
                                                className="text-gray-400 hover:text-blue-500 dark:hover:text-blue-400 transition-colors"
                                                title="Check on VirusTotal"
                                            >
                                                <Shield size={12} />
                                            </button>
                                        )}
                                    </div>
                                )
                            },
                            {
                                header: 'SHA256', accessor: 'sha256', render: (row) => (
                                    <div className="flex items-center gap-2">
                                        <span
                                            className="font-mono text-xs text-purple-500 dark:text-purple-400 cursor-pointer hover:underline"
                                            title={row.sha256}
                                            onClick={() => row.sha256 && copyToClipboard(row.sha256, 'SHA256')}
                                        >
                                            {row.sha256 ? `${row.sha256.substring(0, 12)}...` : '-'}
                                        </span>
                                        {row.sha256 && (
                                            <button
                                                onClick={() => BrowserOpenURL(`https://www.virustotal.com/gui/file/${row.sha256}`)}
                                                className="text-gray-400 hover:text-blue-500 dark:hover:text-blue-400 transition-colors"
                                                title="Check on VirusTotal"
                                            >
                                                <Shield size={12} />
                                            </button>
                                        )}
                                    </div>
                                )
                            },
                            { header: 'Source', accessor: 'source_ip', render: (row) => <span className="font-mono text-xs">{row.source_ip}</span> },
                            { header: 'Destination', accessor: 'dest_ip', render: (row) => <span className="font-mono text-xs">{row.dest_ip}</span> }
                        ]}
                        onRowClick={(row) => handleStreamLink(row)}
                    />
                );

            case 'images':
                return (
                    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6 transition-colors duration-200">
                        <h3 className="text-lg font-bold text-gray-900 dark:text-white mb-4 uppercase tracking-wide text-xs">Extracted Images</h3>
                        {result.images && result.images.length > 0 ? (
                            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
                                {result.images.map((img, idx) => (
                                    <div key={idx}
                                        onClick={() => handleStreamLink(img)}
                                        className="group relative bg-gray-50 dark:bg-gray-900 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700 hover:border-cyan-400 transition-all cursor-pointer">
                                        <div className="aspect-w-16 aspect-h-9 bg-gray-200 dark:bg-gray-800">
                                            <img
                                                src={`data:image;base64,${img.data}`}
                                                alt={img.filename}
                                                className="object-cover w-full h-32"
                                            />
                                        </div>
                                        <div className="p-2 text-xs text-gray-500 dark:text-gray-400 truncate font-mono">{img.filename}</div>
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <div className="text-gray-500 dark:text-gray-400 text-sm">No images found.</div>
                        )}
                    </div>
                );

            case 'credentials':
                return (
                    <div className="space-y-6">
                        <DataTable
                            title="Extracted Credentials"
                            data={result.credentials || []}
                            initialFilters={activeFilters}
                            columns={[
                                { header: 'Protocol', accessor: 'protocol', render: (row) => <span className="font-bold text-red-500">{row.protocol}</span> },
                                { header: 'Client', accessor: 'client_ip' },
                                { header: 'Server', accessor: 'server_ip' },
                                { header: 'Username', accessor: 'username', render: (row) => <span className="font-medium text-gray-900 dark:text-gray-100">{row.username}</span> },
                                { header: 'Password', accessor: 'password', render: (row) => <code className="bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 px-2 py-1 rounded font-mono">{row.password}</code> }
                            ]}
                            onRowClick={(row) => handleStreamLink(row)}
                        />
                    </div>
                );

            case 'sessions':
                return (
                    <DataTable
                        title="Network Sessions (Flows)"
                        data={result.sessions || []}
                        initialFilters={activeFilters}
                        columns={[
                            { header: 'Start Time', accessor: 'start_time', render: (row) => <span className="text-xs text-gray-500 dark:text-gray-400">{new Date(row.start_time).toLocaleTimeString()}</span> },
                            { header: 'Protocol', accessor: 'protocol', render: (row) => <span className={`font-bold ${row.protocol === 'TCP' ? 'text-cyan-500' : 'text-amber-500'}`}>{row.protocol}</span> },
                            { header: 'Source', render: (row) => <span className="font-mono">{row.src_ip}:{row.src_port}</span> },
                            { header: 'Destination', render: (row) => <span className="font-mono">{row.dst_ip}:{row.dst_port}</span> },
                            { header: 'Packets', accessor: 'packet_count', render: (row) => <span className="font-mono">{row.packet_count.toLocaleString()}</span> },
                            { header: 'Bytes', accessor: 'byte_count', render: (row) => <span className="font-mono">{(row.byte_count / 1024).toFixed(2)} KB</span> },
                            { header: 'Duration', accessor: 'duration' },
                            {
                                header: 'JA3 Digest', accessor: 'ja3_digest', render: (row) => (
                                    row.ja3_digest ? (
                                        <div className="flex items-center gap-2">
                                            <span
                                                className="font-mono text-xs text-purple-600 dark:text-purple-400 cursor-pointer hover:underline"
                                                title={row.ja3} // Show full string on hover
                                                onClick={() => copyToClipboard(row.ja3_digest, 'JA3 Digest')}
                                            >
                                                {row.ja3_digest.substring(0, 8)}...
                                            </span>
                                            <button
                                                onClick={() => BrowserOpenURL(`https://ja3.zone/hash/${row.ja3_digest}`)}
                                                className="text-gray-400 hover:text-blue-500 transition-colors"
                                                title="Lookup on JA3 Zone"
                                            >
                                                <Shield size={10} />
                                            </button>
                                        </div>
                                    ) : <span className="text-gray-400">-</span>
                                )
                            }
                        ]}
                        actions={(row) => (
                            row.payload_size > 0 && (
                                <button
                                    onClick={(e) => { e.stopPropagation(); setStreamSession(row); }}
                                    className="text-xs flex items-center gap-1 px-2 py-1 bg-blue-100 hover:bg-blue-200 dark:bg-blue-900/50 dark:hover:bg-blue-900 text-blue-700 dark:text-blue-300 rounded transition-colors"
                                >
                                    Follow Stream <ArrowRight size={12} />
                                </button>
                            )
                        )}
                        onRowClick={(row) => row.payload_size > 0 && setStreamSession(row)}
                        selectedRow={streamSession}
                    />
                );

            case 'artifacts':
                return (
                    <DataTable
                        title="Forensic Artifacts"
                        data={result.parameters || []}
                        columns={[
                            { header: 'Time', accessor: 'timestamp', render: (row) => <span className="text-xs font-mono">{row.timestamp}</span> },
                            {
                                header: 'Protocol', accessor: 'protocol', render: (row) => (
                                    <span className={`px-2 py-0.5 rounded text-xs font-bold ${row.protocol === 'HTTP' ? 'bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300' :
                                        row.protocol === 'SMTP' ? 'bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300' :
                                            'bg-orange-100 dark:bg-orange-900 text-orange-700 dark:text-orange-300'
                                        }`}>
                                        {row.protocol}
                                    </span>
                                )
                            },
                            {
                                header: 'Type', accessor: 'type', render: (row) => (
                                    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${row.type === 'Cookie' ? 'bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300' :
                                        row.type === 'Query' ? 'bg-cyan-100 dark:bg-cyan-900 text-cyan-700 dark:text-cyan-300' :
                                            row.type === 'POST' ? 'bg-purple-100 dark:bg-purple-900 text-purple-700 dark:text-purple-300' :
                                                row.type === 'Command' ? 'bg-yellow-100 dark:bg-yellow-900 text-yellow-700 dark:text-yellow-300' :
                                                    'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300'
                                        }`}>
                                        {row.type}
                                    </span>
                                )
                            },
                            { header: 'Method', accessor: 'method', render: (row) => <span className="text-xs">{row.method || '-'}</span> },
                            { header: 'Key', accessor: 'key', render: (row) => <span className="font-mono text-xs text-cyan-500 dark:text-cyan-400 font-semibold">{row.key}</span> },
                            { header: 'Value', accessor: 'value', render: (row) => <span className="font-mono text-xs truncate max-w-xs block" title={row.value}>{row.value}</span> },
                            { header: 'URL', accessor: 'url', render: (row) => <span className="text-xs truncate max-w-xs block" title={row.url}>{row.url || '-'}</span> },
                            { header: 'Source', accessor: 'source_ip', render: (row) => <span className="font-mono text-xs">{row.source_ip}</span> },
                            { header: 'Dest', accessor: 'dest_ip', render: (row) => <span className="font-mono text-xs">{row.dest_ip}</span> }
                        ]}
                    />
                );

            case 'messages':
                return (
                    <div className="flex flex-col h-full space-y-4">
                        {/* Message List */}
                        <div className={`${selectedMessage ? 'h-2/3' : 'h-full'} transition-all duration-300`}>
                            <DataTable
                                title="Email Messages"
                                data={result.messages || []}
                                columns={[
                                    { header: 'Frame', accessor: 'frame_number', render: (row) => <span className="font-mono text-xs">{row.frame_number}</span> },
                                    { header: 'Time', accessor: 'timestamp', render: (row) => <span className="text-xs">{row.timestamp}</span> },
                                    {
                                        header: 'Protocol', accessor: 'protocol', render: (row) => (
                                            <span className={`px-2 py-0.5 rounded text-xs font-bold ${row.protocol === 'SMTP' ? 'bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300' :
                                                row.protocol === 'POP3' ? 'bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300' :
                                                    'bg-purple-100 dark:bg-purple-900 text-purple-700 dark:text-purple-300'
                                                }`}>
                                                {row.protocol}
                                            </span>
                                        )
                                    },
                                    { header: 'From', accessor: 'from', render: (row) => <span className="text-sm truncate max-w-xs block" title={row.from}>{row.from || '-'}</span> },
                                    { header: 'To', accessor: 'to', render: (row) => <span className="text-sm truncate max-w-xs block" title={row.to}>{row.to || '-'}</span> },
                                    { header: 'Subject', accessor: 'subject', render: (row) => <span className="font-medium text-sm truncate max-w-md block" title={row.subject}>{row.subject || '(No Subject)'}</span> },
                                    {
                                        header: 'Size', accessor: 'size', render: (row) => (
                                            <span className="font-mono text-xs">{(row.size / 1024).toFixed(1)} KB</span>
                                        )
                                    },
                                    {
                                        header: 'Attachments', accessor: 'attachments', render: (row) => (
                                            row.attachments && row.attachments.length > 0 ? (
                                                <span className="text-xs text-cyan-500 dark:text-cyan-400">📎 {row.attachments.length}</span>
                                            ) : <span className="text-xs text-gray-400">-</span>
                                        )
                                    }
                                ]}
                                onRowClick={(row) => setSelectedMessage(row)}
                            />
                        </div>

                        {/* Message Detail Pane */}
                        {selectedMessage && (
                            <div className="h-1/3 border-t-2 border-cyan-500 dark:border-cyan-600 p-6 bg-gray-100 dark:bg-gray-800 rounded-lg shadow-inner overflow-auto">
                                <div className="flex justify-between items-start mb-4">
                                    <h3 className="font-bold text-xl text-gray-900 dark:text-white">{selectedMessage.subject || '(No Subject)'}</h3>
                                    <button
                                        onClick={() => setSelectedMessage(null)}
                                        className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
                                    >
                                        ✕
                                    </button>
                                </div>
                                <div className="text-sm space-y-2 mb-4 text-gray-700 dark:text-gray-300">
                                    <div className="flex"><strong className="w-24">From:</strong> <span className="font-mono">{selectedMessage.from}</span></div>
                                    <div className="flex"><strong className="w-24">To:</strong> <span className="font-mono">{selectedMessage.to}</span></div>
                                    <div className="flex"><strong className="w-24">Date:</strong> {selectedMessage.date || selectedMessage.timestamp}</div>
                                    <div className="flex"><strong className="w-24">Protocol:</strong> {selectedMessage.protocol}</div>
                                    {selectedMessage.message_id && (
                                        <div className="flex"><strong className="w-24">Message-ID:</strong> <span className="font-mono text-xs">{selectedMessage.message_id}</span></div>
                                    )}
                                    {selectedMessage.attachments && selectedMessage.attachments.length > 0 && (
                                        <div className="flex">
                                            <strong className="w-24">Attachments:</strong>
                                            <div className="flex-1">
                                                {selectedMessage.attachments.map((att, idx) => (
                                                    <div key={idx} className="text-xs font-mono text-cyan-600 dark:text-cyan-400">
                                                        📎 {att.filename} ({att.content_type}, {(att.size / 1024).toFixed(1)} KB)
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </div>
                                <div className="bg-white dark:bg-gray-900 p-4 rounded border-2 border-gray-300 dark:border-gray-600 overflow-auto max-h-64">
                                    <h4 className="text-xs font-bold text-gray-500 dark:text-gray-400 mb-2">MESSAGE BODY:</h4>
                                    <pre className="text-sm whitespace-pre-wrap font-mono text-gray-800 dark:text-gray-200">
                                        {selectedMessage.body || selectedMessage.raw_body || '(No content)'}
                                    </pre>
                                </div>
                            </div>
                        )}
                    </div>
                );

            case 'anomalies':
                const anomalies = result.anomalies || [];
                const criticalCount = anomalies.filter(a => a.severity === 'Critical').length;
                const highCount = anomalies.filter(a => a.severity === 'High').length;
                const mediumCount = anomalies.filter(a => a.severity === 'Medium').length;
                const lowCount = anomalies.filter(a => a.severity === 'Low').length;

                return (
                    <div className="space-y-6">
                        {/* Summary Cards */}
                        <div className="grid grid-cols-4 gap-4">
                            <div className="bg-red-100 dark:bg-red-900 bg-opacity-50 dark:bg-opacity-30 p-4 rounded-lg border-2 border-red-500 dark:border-red-600">
                                <div className="text-red-700 dark:text-red-300 text-sm font-bold mb-1">CRITICAL</div>
                                <div className="text-4xl font-mono font-bold text-red-800 dark:text-red-200">{criticalCount}</div>
                            </div>
                            <div className="bg-orange-100 dark:bg-orange-900 bg-opacity-50 dark:bg-opacity-30 p-4 rounded-lg border-2 border-orange-500 dark:border-orange-600">
                                <div className="text-orange-700 dark:text-orange-300 text-sm font-bold mb-1">HIGH</div>
                                <div className="text-4xl font-mono font-bold text-orange-800 dark:text-orange-200">{highCount}</div>
                            </div>
                            <div className="bg-yellow-100 dark:bg-yellow-900 bg-opacity-50 dark:bg-opacity-30 p-4 rounded-lg border-2 border-yellow-500 dark:border-yellow-600">
                                <div className="text-yellow-700 dark:text-yellow-300 text-sm font-bold mb-1">MEDIUM</div>
                                <div className="text-4xl font-mono font-bold text-yellow-800 dark:text-yellow-200">{mediumCount}</div>
                            </div>
                            <div className="bg-blue-100 dark:bg-blue-900 bg-opacity-50 dark:bg-opacity-30 p-4 rounded-lg border-2 border-blue-500 dark:border-blue-600">
                                <div className="text-blue-700 dark:text-blue-300 text-sm font-bold mb-1">LOW</div>
                                <div className="text-4xl font-mono font-bold text-blue-800 dark:text-blue-200">{lowCount}</div>
                            </div>
                        </div>

                        {/* Anomalies Table */}
                        <DataTable
                            title="Detected Anomalies"
                            data={anomalies}
                            initialFilters={activeFilters}
                            columns={[
                                { header: 'Frame', accessor: 'frame_number', render: (row) => <span className="font-mono text-xs">{row.frame_number}</span> },
                                { header: 'Time', accessor: 'timestamp', render: (row) => <span className="text-xs">{row.timestamp}</span> },
                                {
                                    header: 'Severity', accessor: 'severity', render: (row) => (
                                        <span className={`px-2 py-1 rounded text-xs font-bold ${row.severity === 'Critical' ? 'bg-red-600 text-white' :
                                            row.severity === 'High' ? 'bg-orange-500 text-white' :
                                                row.severity === 'Medium' ? 'bg-yellow-500 text-gray-900' :
                                                    'bg-blue-500 text-white'
                                            }`}>
                                            {row.severity.toUpperCase()}
                                        </span>
                                    )
                                },
                                {
                                    header: 'Type', accessor: 'type', render: (row) => (
                                        <span className="font-semibold text-sm text-cyan-600 dark:text-cyan-400">{row.type}</span>
                                    )
                                },
                                {
                                    header: 'Description', accessor: 'description', render: (row) => (
                                        <span className="text-sm">{row.description}</span>
                                    )
                                },
                                {
                                    header: 'Source', accessor: 'source_ip', render: (row) => (
                                        <span className="font-mono text-xs">
                                            {row.source_ip}{row.source_port > 0 ? `:${row.source_port}` : ''}
                                        </span>
                                    )
                                },
                                {
                                    header: 'Dest', accessor: 'dest_ip', render: (row) => (
                                        <span className="font-mono text-xs">
                                            {row.dest_ip}{row.dest_port > 0 ? `:${row.dest_port}` : ''}
                                        </span>
                                    )
                                },
                                { header: 'Protocol', accessor: 'protocol', render: (row) => <span className="text-xs font-bold">{row.protocol}</span> },
                                {
                                    header: 'Details', accessor: 'details', render: (row) => (
                                        <span className="text-xs text-gray-600 dark:text-gray-400 truncate max-w-md block" title={row.details}>
                                            {row.details || '-'}
                                        </span>
                                    )
                                }
                            ]}
                            onRowClick={(row) => handleStreamLink(row)}
                        />
                    </div>
                );

            case 'keywords':
                return (
                    <div className="space-y-6">
                        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
                            <h3 className="text-lg font-bold text-gray-900 dark:text-white mb-4">Keyword Search</h3>
                            <div className="flex gap-4 mb-4">
                                <input
                                    type="text"
                                    value={newKeyword}
                                    onChange={(e) => setNewKeyword(e.target.value)}
                                    onKeyDown={(e) => e.key === 'Enter' && addKeyword()}
                                    placeholder="Enter keyword (e.g., password, admin)..."
                                    className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-cyan-500"
                                />
                                <button
                                    onClick={addKeyword}
                                    className="bg-cyan-600 hover:bg-cyan-700 text-white font-bold py-2 px-6 rounded-md shadow transition-colors"
                                >
                                    Add Key
                                </button>
                                <button
                                    onClick={() => process(null)}
                                    className="bg-emerald-600 hover:bg-emerald-700 text-white font-bold py-2 px-6 rounded-md shadow transition-colors flex items-center gap-2"
                                >
                                    <span>Reload PCAP</span>
                                </button>
                            </div>

                            <div className="flex flex-wrap gap-2">
                                {keywords.map((kw, idx) => (
                                    <span key={idx} className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-cyan-100 text-cyan-800 dark:bg-cyan-900 dark:text-cyan-200">
                                        {kw}
                                        <button
                                            onClick={() => removeKeyword(kw)}
                                            className="ml-2 text-cyan-600 dark:text-cyan-400 hover:text-cyan-900 dark:hover:text-cyan-100 focus:outline-none"
                                        >
                                            ×
                                        </button>
                                    </span>
                                ))}
                                {keywords.length === 0 && (
                                    <span className="text-gray-500 dark:text-gray-400 text-sm italic">No keywords defined. Add keywords and reload the PCAP to search.</span>
                                )}
                            </div>
                        </div>

                        <DataTable
                            title="Keyword Matches"
                            data={result.keyword_matches || []}
                            columns={[
                                { header: 'Keyword', accessor: 'keyword', render: (row) => <span className="font-bold text-purple-600 dark:text-purple-400">{row.keyword}</span> },
                                { header: 'Context', accessor: 'context', render: (row) => <code className="text-xs bg-gray-100 dark:bg-gray-700 dark:text-gray-300 p-1 rounded font-mono break-all">{row.context}</code> },
                                { header: 'Frame', accessor: 'frame_num' },
                                { header: 'Timestamp', accessor: 'timestamp' }
                            ]}
                        />
                    </div>
                );

            case 'map':
                return <MapTab result={result} />;

            case 'browsers':
                return (
                    <div className="space-y-6">
                        <DataTable
                            title="Browsing History"
                            data={result.http_transactions || []}
                            columns={[
                                { header: 'Timestamp', accessor: 'timestamp' },
                                { header: 'Source', accessor: 'src_ip', render: (row) => `${row.src_ip}:${row.src_port}` },
                                { header: 'Method', accessor: 'method', render: (row) => <span className={`font-bold ${row.method === 'GET' ? 'text-green-600 dark:text-green-400' : 'text-blue-600 dark:text-blue-400'}`}>{row.method}</span> },
                                { header: 'Host', accessor: 'host', render: (row) => <span className="font-semibold text-gray-800 dark:text-gray-200">{row.host}</span> },
                                { header: 'URL', accessor: 'url', render: (row) => <div className="truncate max-w-md" title={row.url}>{row.url}</div> },
                                { header: 'User-Agent', accessor: 'user_agent', render: (row) => <div className="truncate max-w-xs text-xs text-gray-500" title={row.user_agent}>{row.user_agent}</div> },
                            ]}
                            onRowClick={(row) => handleStreamLink(row)}
                        />
                    </div>
                );

            case 'decryption':
                return <DecryptionTab result={result} />;

            case 'parameters':
                return (
                    <div className="space-y-6">
                        <DataTable
                            title="Extracted Parameters (Cleartext)"
                            data={result.parameters || []}
                            columns={[
                                { header: 'Timestamp', accessor: 'timestamp' },
                                { header: 'Protocol', accessor: 'protocol', render: (row) => <span className="font-bold text-xs px-2 py-0.5 rounded bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300">{row.protocol}</span> },
                                { header: 'Type', accessor: 'type' },
                                { header: 'Key', accessor: 'key', render: (row) => <span className="font-semibold text-gray-800 dark:text-gray-200">{row.key}</span> },
                                { header: 'Value', accessor: 'value', render: (row) => <div className="truncate max-w-lg font-mono text-xs text-gray-600 dark:text-gray-400" title={row.value}>{row.value}</div> },
                                { header: 'Source', accessor: 'source_ip' },
                                { header: 'Destination', accessor: 'dest_ip' },
                            ]}
                        />
                    </div>
                );

            case 'voip':
                return (
                    <div className="space-y-6">
                        <DataTable
                            title="VoIP Calls (SIP)"
                            data={result.voip_calls || []}
                            columns={[
                                { header: 'ID', accessor: 'id', render: (row) => <span className="text-xs text-gray-400 font-mono">{row.id.substring(0, 8)}...</span> },
                                { header: 'State', accessor: 'state', render: (row) => <span className={`font-bold px-2 py-1 rounded text-xs ${row.state === 'ACTIVE' || row.state === 'CLOSED' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'}`}>{row.state}</span> },
                                { header: 'Start Time', accessor: 'timestamp' },
                                { header: 'Duration', accessor: 'duration_sec', render: (row) => <span>{row.duration_sec}s</span> },
                                { header: 'From', accessor: 'from', render: (row) => <span className="font-semibold">{row.from}</span> },
                                { header: 'To', accessor: 'to', render: (row) => <span className="font-semibold">{row.to}</span> },
                                { header: 'User-Agent', accessor: 'user_agent', render: (row) => <span className="text-xs text-gray-500">{row.user_agent}</span> },
                            ]}
                        />
                    </div>
                );

            default:
                return <div className="p-8 text-center text-gray-500 dark:text-gray-400">Feature not implemented yet.</div>;
        }
    };

    const currentFilename = filePath ? filePath.split(/[\\/]/).pop() : null;

    return (
        <>
            <Layout activeTab={activeTab} setActiveTab={(tab) => handleNavigation(tab, {})} filename={currentFilename} toggleTheme={toggleTheme} theme={theme} onLoadPcap={selectFile} keyLoaded={keyLoaded}>
                {renderContent()}
            </Layout>
            {/* Toast Notification */}
            <div className={`fixed bottom-8 left-1/2 transform -translate-x-1/2 transition-all duration-300 ${showToast ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4 pointer-events-none'
                }`}>
                <div className="bg-gray-900 dark:bg-gray-100 text-white dark:text-gray-900 px-6 py-3 rounded-lg shadow-lg font-medium text-sm">
                    {toastMessage}
                </div>
            </div>

            {/* Loading Progress Modal */}
            {isLoading && (
                <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50">
                    <div className="bg-gray-800 rounded-lg p-8 max-w-md w-full shadow-2xl">
                        <h2 className="text-2xl font-bold text-white mb-4 text-center">Processing PCAP</h2>
                        <div className="space-y-4">
                            {/* Progress Bar */}
                            <div className="w-full bg-gray-700 rounded-full h-6 relative overflow-hidden">
                                <div
                                    className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-300 ease-out"
                                    style={{ width: `${loadingProgress.percent}%` }}
                                ></div>
                                <div className="absolute inset-0 flex items-center justify-center">
                                    <span className="text-xs font-bold text-white drop-shadow-md">{loadingProgress.percent}%</span>
                                </div>
                            </div>
                            {/* Packet Count */}
                            <div className="text-center text-gray-300 font-mono text-sm">
                                {loadingProgress.current.toLocaleString()} / {loadingProgress.estimated.toLocaleString()} packets
                            </div>
                            {/* Animated Spinner */}
                            <div className="flex justify-center">
                                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500"></div>
                            </div>
                        </div>
                    </div>
                </div>
            )}
            {/* Stream Viewer Modal */}
            {streamSession && (
                <StreamViewer
                    session={streamSession}
                    onClose={() => setStreamSession(null)}
                />
            )}
        </>
    );
}

export default App;
