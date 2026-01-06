import React, { useMemo } from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend } from 'recharts';
import { Activity, Shield, FileText, Database, Server, Globe, Key, AlertTriangle } from 'lucide-react';
import DataTable from './DataTable';

const Dashboard = ({ data, onNavigate }) => {
    if (!data) return <div className="p-8 text-center text-gray-500">Please select a PCAP file to begin analysis.</div>;

    // --- Data Preparation ---
    const hostCount = data.hosts ? data.hosts.length : 0;
    const credCount = data.credentials ? data.credentials.length : 0;
    const filesCount = data.files ? data.files.length : 0;
    const packetCount = data.metadata ? data.metadata.total_packets : (data.message ? parseInt(data.message.match(/Processed (\d+) packets/)?.[1] || 0) : 0);
    const duration = data.metadata ? data.metadata.duration : "N/A";
    const anomalyCount = data.anomalies ? data.anomalies.length : 0;

    // Protocol Stats
    const protocolStats = data.protocol_stats || { TCP: 0, UDP: 0, ICMP: 0 };
    const protocolData = [
        { name: 'TCP', value: protocolStats.TCP || 0, color: '#06b6d4' }, // Cyan
        { name: 'UDP', value: protocolStats.UDP || 0, color: '#f59e0b' }, // Amber
        { name: 'ICMP', value: protocolStats.ICMP || 0, color: '#0ea5e9' }, // Sky
        { name: 'Other', value: (packetCount - (protocolStats.TCP + protocolStats.UDP + protocolStats.ICMP)) || 0, color: '#64748b' }
    ].filter(d => d.value > 0);

    // Frontend Aggregation for Top Talkers (if needed) across sessions
    const { topSources, topDestinations } = useMemo(() => {
        if (!data.sessions) return { topSources: [], topDestinations: [] };

        const sources = {};
        const dests = {};

        data.sessions.forEach(s => {
            sources[s.src_ip] = (sources[s.src_ip] || 0) + s.byte_count;
            dests[s.dst_ip] = (dests[s.dst_ip] || 0) + s.byte_count;
        });

        const sortAndSlice = (obj) => Object.entries(obj)
            .map(([ip, bytes]) => ({ name: ip, value: bytes }))
            .sort((a, b) => b.value - a.value)
            .slice(0, 5);

        return {
            topSources: sortAndSlice(sources),
            topDestinations: sortAndSlice(dests)
        };
    }, [data.sessions]);


    // Anomaly Stats (Severity)
    const anomalyStats = useMemo(() => {
        if (!data.anomalies) return [];
        const counts = { Low: 0, Medium: 0, High: 0, Critical: 0 };
        data.anomalies.forEach(a => {
            if (counts[a.severity] !== undefined) counts[a.severity]++;
        });
        return [
            { name: 'Low', value: counts.Low, color: '#eab308' },      // Yellow
            { name: 'Medium', value: counts.Medium, color: '#f97316' }, // Orange
            { name: 'High', value: counts.High, color: '#ef4444' },     // Red
            { name: 'Critical', value: counts.Critical, color: '#a855f7' } // Purple
        ].filter(d => d.value > 0);
    }, [data.anomalies]);

    // Services (Top 5 Ports)
    const serviceStats = data.service_stats || {};
    const serviceData = Object.entries(serviceStats)
        .map(([port, count]) => ({
            name: port,
            value: count
        }))
        .sort((a, b) => b.value - a.value)
        .slice(0, 5);

    // Common Chart Props
    const tooltipStyle = {
        backgroundColor: '#1e293b', // Slate 800
        borderColor: '#334155',     // Slate 700
        color: '#f8fafc',           // Slate 50
        borderRadius: '0.375rem',
        fontSize: '12px',
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
    };

    return (
        <div className="space-y-6 animate-fade-in">
            {/* Case Information Card */}
            {data.metadata && (
                <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 transition-colors mb-6">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                        <div>
                            <p className="text-gray-500 dark:text-gray-400 text-xs uppercase tracking-wider">Filename</p>
                            <p className="font-mono font-medium text-gray-900 dark:text-white truncate" title={data.metadata.filename}>{data.metadata.filename}</p>
                        </div>
                        <div>
                            <p className="text-gray-500 dark:text-gray-400 text-xs uppercase tracking-wider">MD5 Hash</p>
                            <p className="font-mono text-xs text-gray-900 dark:text-white break-all">{data.metadata.md5}</p>
                        </div>
                        <div>
                            <p className="text-gray-500 dark:text-gray-400 text-xs uppercase tracking-wider">Size</p>
                            <p className="font-mono text-gray-900 dark:text-white">{(data.metadata.size / 1024).toFixed(2)} KB</p>
                        </div>
                        <div>
                            <p className="text-gray-500 dark:text-gray-400 text-xs uppercase tracking-wider">Duration</p>
                            <p className="font-mono text-cyan-600 dark:text-cyan-400 font-bold">{data.metadata.duration}</p>
                        </div>
                    </div>
                </div>
            )}

            {/* Top Summary Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {[
                    { label: 'Total Packets', value: packetCount.toLocaleString(), icon: Activity, color: 'text-blue-500', nav: 'sessions', filter: {} },
                    { label: 'Hosts Discovered', value: hostCount, icon: Server, color: 'text-cyan-500', nav: 'hosts', filter: {} },
                    { label: 'Credentials Found', value: credCount, icon: Key, color: 'text-red-500', nav: 'credentials', filter: {} },
                    { label: 'Files Extracted', value: filesCount, icon: FileText, color: 'text-purple-500', nav: 'files', filter: {} },
                ].map((stat, idx) => (
                    <div
                        key={idx}
                        onClick={() => onNavigate && onNavigate(stat.nav, stat.filter)}
                        className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 hover:border-cyan-400 dark:hover:border-cyan-500 hover:shadow-md transition-all cursor-pointer group"
                    >
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-xs font-bold text-gray-500 dark:text-gray-400 uppercase tracking-widest">{stat.label}</p>
                                <p className="mt-2 text-3xl font-bold font-mono text-gray-900 dark:text-white group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors">{stat.value}</p>
                            </div>
                            <stat.icon className={`h-8 w-8 ${stat.color} opacity-70 group-hover:scale-110 transition-transform`} />
                        </div>
                    </div>
                ))}
            </div>

            {/* Main Charts Row */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Timeline Chart */}
                <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 lg:col-span-2">
                    <h3 className="text-sm font-bold text-gray-900 dark:text-white mb-6 uppercase tracking-wider flex items-center gap-2">
                        <Activity size={16} /> Traffic Activity
                    </h3>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={data.timeline}>
                                <defs>
                                    <linearGradient id="colorBytes" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.8} />
                                        <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} opacity={0.5} />
                                <XAxis dataKey="timestamp" stroke="#94a3b8" tick={{ fontSize: 10 }} minTickGap={40} />
                                <YAxis stroke="#94a3b8" tick={{ fontSize: 10 }} tickFormatter={(val) => `${(val / 1024).toFixed(0)}K`} />
                                <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: '#fff' }} />
                                <Area type="monotone" dataKey="bytes" stroke="#06b6d4" fillOpacity={1} fill="url(#colorBytes)" />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* Protocol Pie Chart */}
                <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
                    <h3 className="text-sm font-bold text-gray-900 dark:text-white mb-6 uppercase tracking-wider flex items-center gap-2">
                        <Globe size={16} /> Protocols
                    </h3>
                    <div className="h-64 relative">
                        <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                                <Pie
                                    data={protocolData}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={60}
                                    outerRadius={80}
                                    paddingAngle={5}
                                    dataKey="value"
                                    cursor="pointer"
                                    onClick={(data) => onNavigate && onNavigate('sessions', { protocol: data.name })}
                                >
                                    {protocolData.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={entry.color} stroke="none" className="hover:opacity-80 transition-opacity" />
                                    ))}
                                </Pie>
                                <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: '#fff' }} />
                                <Legend verticalAlign="bottom" height={36} iconType="circle" wrapperStyle={{ fontSize: '12px', color: '#94a3b8' }} />
                            </PieChart>
                        </ResponsiveContainer>
                        {/* Center Label */}
                        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-[60%] text-center pointer-events-none">
                            <span className="block text-2xl font-bold text-gray-900 dark:text-white">{protocolData.length}</span>
                            <span className="text-xs text-gray-500">TYPES</span>
                        </div>
                    </div>
                </div>
            </div>

            {/* Secondary Charts Row (Top Talkers) */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {/* Top Sources */}
                <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
                    <h3 className="text-sm font-bold text-gray-900 dark:text-white mb-4 uppercase tracking-wider">Top Sources (Bytes)</h3>
                    <div className="h-48">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart
                                layout="vertical"
                                data={topSources}
                                margin={{ top: 5, right: 30, left: 40, bottom: 5 }}
                            >
                                <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#334155" opacity={0.3} />
                                <XAxis type="number" stroke="#94a3b8" fontSize={10} tickFormatter={(val) => (val / 1024).toFixed(0) + 'K'} />
                                <YAxis dataKey="name" type="category" stroke="#94a3b8" fontSize={10} width={80} />
                                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: '#334155', opacity: 0.2 }} formatter={(val) => (val / 1024).toFixed(2) + ' KB'} />
                                <Bar
                                    dataKey="value"
                                    fill="#8b5cf6"
                                    radius={[0, 4, 4, 0]}
                                    cursor="pointer"
                                    onClick={(data) => onNavigate && onNavigate('sessions', { src_ip: data.name })}
                                />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* Top Destinations */}
                <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
                    <h3 className="text-sm font-bold text-gray-900 dark:text-white mb-4 uppercase tracking-wider">Top Destinations (Bytes)</h3>
                    <div className="h-48">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart
                                layout="vertical"
                                data={topDestinations}
                                margin={{ top: 5, right: 30, left: 40, bottom: 5 }}
                            >
                                <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#334155" opacity={0.3} />
                                <XAxis type="number" stroke="#94a3b8" fontSize={10} tickFormatter={(val) => (val / 1024).toFixed(0) + 'K'} />
                                <YAxis dataKey="name" type="category" stroke="#94a3b8" fontSize={10} width={80} />
                                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: '#334155', opacity: 0.2 }} formatter={(val) => (val / 1024).toFixed(2) + ' KB'} />
                                <Bar
                                    dataKey="value"
                                    fill="#ec4899"
                                    radius={[0, 4, 4, 0]}
                                    cursor="pointer"
                                    onClick={(data) => onNavigate && onNavigate('sessions', { dst_ip: data.name })}
                                />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* Anomalies by Severity */}
                <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
                    <h3 className="text-sm font-bold text-gray-900 dark:text-white mb-4 uppercase tracking-wider flex items-center gap-2">
                        <AlertTriangle size={16} /> Anomalies
                    </h3>
                    <div className="h-48 relative">
                        {anomalyStats.length > 0 ? (
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={anomalyStats}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={40}
                                        outerRadius={60}
                                        paddingAngle={5}
                                        dataKey="value"
                                        cursor="pointer"
                                        onClick={(data) => onNavigate && onNavigate('anomalies', { severity: data.name })}
                                    >
                                        {anomalyStats.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={entry.color} stroke="none" className="hover:opacity-80 transition-opacity" />
                                        ))}
                                    </Pie>
                                    <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: '#fff' }} />
                                    <Legend verticalAlign="bottom" height={36} iconType="circle" wrapperStyle={{ fontSize: '12px', color: '#94a3b8' }} />
                                </PieChart>
                            </ResponsiveContainer>
                        ) : (
                            <div className="flex items-center justify-center h-full text-gray-500 text-xs">No anomalies detected</div>
                        )}
                        {/* Center Label */}
                        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-[60%] text-center pointer-events-none">
                            <span className="block text-xl font-bold text-gray-900 dark:text-white">{anomalyCount}</span>
                        </div>
                    </div>
                </div>

                {/* Top Services */}
                <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 lg:col-span-3">
                    <h3 className="text-sm font-bold text-gray-900 dark:text-white mb-4 uppercase tracking-wider">Top Services (Ports)</h3>
                    <div className="h-48">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart
                                layout="vertical"
                                data={serviceData}
                                margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                            >
                                <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#334155" opacity={0.3} />
                                <XAxis type="number" stroke="#94a3b8" fontSize={10} />
                                <YAxis dataKey="name" type="category" stroke="#94a3b8" fontSize={10} width={40} />
                                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: '#334155', opacity: 0.2 }} />
                                <Bar
                                    dataKey="value"
                                    fill="#10b981"
                                    radius={[0, 4, 4, 0]}
                                    cursor="pointer"
                                    onClick={(data) => onNavigate && onNavigate('sessions', { dst_port: data.name })}
                                />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>

            {/* Recent DNS (Using DataTable) */}
            <DataTable
                title="Recent DNS Queries"
                data={data.dns_records ? data.dns_records.slice(0, 5) : []}
                columns={[
                    { header: 'Time', accessor: 'timestamp' },
                    { header: 'Query', accessor: 'query', render: (row) => <span className="font-medium text-gray-800 dark:text-gray-200">{row.query}</span> },
                    { header: 'Type', accessor: 'type', render: (row) => <span className="px-2 py-0.5 rounded text-xs bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 font-mono">{row.type}</span> },
                    { header: 'Answers', accessor: 'answers', render: (row) => <span className="text-gray-500 dark:text-gray-400 truncate max-w-xs block">{row.answers}</span> }
                ]}
            />
        </div>
    );
};

export default Dashboard;
