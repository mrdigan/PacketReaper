import React from 'react';
import DataTable from './DataTable';
import { AlertTriangle, AlertOctagon, Info } from 'lucide-react';

const AnomaliesTab = ({ result }) => {
    const anomalies = result?.anomalies || [];

    // Helper to render severity badge
    const renderSeverity = (row) => {
        let color = "bg-gray-100 text-gray-800";
        let icon = <Info size={14} />;

        const severity = (row.severity || "").toLowerCase();

        if (severity === "critical" || severity === "high") {
            color = "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300 border border-red-200 dark:border-red-800";
            icon = <AlertOctagon size={14} className="text-red-600 dark:text-red-400" />;
        } else if (severity === "medium") {
            color = "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300 border border-amber-200 dark:border-amber-800";
            icon = <AlertTriangle size={14} className="text-amber-600 dark:text-amber-400" />;
        } else if (severity === "low") {
            color = "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300 border border-blue-200 dark:border-blue-800";
            icon = <Info size={14} className="text-blue-600 dark:text-blue-400" />;
        }

        return (
            <span className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium w-fit ${color}`}>
                {icon}
                {row.severity}
            </span>
        );
    };

    const columns = [
        {
            header: 'Severity',
            accessor: 'severity',
            render: renderSeverity
        },
        {
            header: 'Type',
            accessor: 'type',
            render: (row) => <span className="font-semibold text-gray-700 dark:text-gray-300">{row.type}</span>
        },
        {
            header: 'Target',
            accessor: 'target_ip',
            render: (row) => (
                <div className="font-mono text-xs">
                    <div className="text-blue-600 dark:text-blue-400">{row.target_ip}:{row.target_port}</div>
                    {row.hostname && <div className="text-gray-400 text-[10px]">{row.hostname}</div>}
                </div>
            )
        },
        {
            header: 'Description',
            accessor: 'description',
            render: (row) => <span className="text-gray-600 dark:text-gray-400">{row.description}</span>
        },
        {
            header: 'Timestamp',
            accessor: 'timestamp',
            render: (row) => <span className="text-xs text-gray-500">{row.timestamp}</span>
        }
    ];

    return (
        <div className="space-y-6">
            <DataTable
                title="Network Anomalies"
                data={anomalies}
                columns={columns}
                defaultSortField="severity"
            />
        </div>
    );
};

export default AnomaliesTab;
