import React, { useState, useMemo } from 'react';
import { ChevronUp, ChevronDown, ArrowUpDown, Filter, X } from 'lucide-react';

const DataTable = ({ title, data, columns, rowKey, onRowClick, actions, initialFilters, selectedRow }) => {
    const [sortConfig, setSortConfig] = useState({ key: null, direction: 'asc' });
    const [filters, setFilters] = useState(initialFilters || {});
    const [activeFilterCol, setActiveFilterCol] = useState(null);

    // Sync initialFilters if they change (externally driven)
    React.useEffect(() => {
        if (initialFilters) {
            setFilters(initialFilters);
        }
    }, [initialFilters]);

    // --- Helpers ---
    const getNestedValue = (obj, path) => {
        if (!path) return '';
        return path.split('.').reduce((o, i) => (o ? o[i] : ''), obj);
    };

    const handleSort = (accessor) => {
        let direction = 'asc';
        if (sortConfig.key === accessor && sortConfig.direction === 'asc') {
            direction = 'desc';
        }
        setSortConfig({ key: accessor, direction });
    };

    const handleFilterChange = (accessor, value) => {
        setFilters(prev => {
            const next = { ...prev, [accessor]: value };
            if (!value) delete next[accessor];
            return next;
        });
    };

    const clearFilter = (accessor) => {
        const newFilters = { ...filters };
        delete newFilters[accessor];
        setFilters(newFilters);
    };

    // --- Virtualization State ---
    const [scrollTop, setScrollTop] = useState(0);
    const scrollContainerRef = React.useRef(null);
    const ROW_HEIGHT = 36; // Approximate height of a row in px
    const OVERSCAN = 10; // Extra rows to render

    const handleScroll = (e) => {
        setScrollTop(e.target.scrollTop);
    };

    // --- Processing ---
    const processedData = useMemo(() => {
        if (!data) return [];
        let processed = [...data];

        // 1. Filter
        Object.keys(filters).forEach(key => {
            const filterValue = filters[key].toLowerCase();
            processed = processed.filter(item => {
                const val = item[key];
                if (val == null) return false; // Filter out nulls if searching
                return String(val).toLowerCase().includes(filterValue);
            });
        });

        // 2. Sort
        if (sortConfig.key) {
            processed.sort((a, b) => {
                // Determine values (handle potential render/accessor complexity?)
                // For now assuming accessor points to data
                let aVal = a[sortConfig.key];
                let bVal = b[sortConfig.key];

                // Simple string/number comparison
                if (typeof aVal === 'string') aVal = aVal.toLowerCase();
                if (typeof bVal === 'string') bVal = bVal.toLowerCase();

                if (aVal < bVal) return sortConfig.direction === 'asc' ? -1 : 1;
                if (aVal > bVal) return sortConfig.direction === 'asc' ? 1 : -1;
                return 0;
            });
        }

        return processed;
    }, [data, sortConfig, filters]);

    // Virtualization Calculations
    const totalHeight = processedData.length * ROW_HEIGHT;
    const clientHeight = scrollContainerRef.current ? scrollContainerRef.current.clientHeight : 600;

    // Safety check for NaN or infinite
    const safeTotalHeight = isNaN(totalHeight) ? 0 : totalHeight;

    const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
    const endIndex = Math.min(processedData.length, Math.ceil((scrollTop + clientHeight) / ROW_HEIGHT) + OVERSCAN);

    const visibleData = processedData.slice(startIndex, endIndex);
    const topPadding = startIndex * ROW_HEIGHT;
    const bottomPadding = Math.max(0, safeTotalHeight - (endIndex * ROW_HEIGHT));

    // Should we show empty state if data prop is empty, or if filtered result is empty?
    // User probably wants to see headers even if filter results in 0 rows.
    if (!data || data.length === 0) {
        return (
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6 text-center text-gray-500">
                No data available for {title}
            </div>
        );
    }

    // --- CSV Export ---
    const downloadCSV = () => {
        if (!processedData || processedData.length === 0) return;

        // Filter out columns that don't have an accessor (like actions)
        const exportableColumns = columns.filter(col => col.accessor);

        const headers = exportableColumns.map(col => col.header).join(',');

        const rows = processedData.map(row => {
            return exportableColumns.map(col => {
                let val = getNestedValue(row, col.accessor);
                if (val === null || val === undefined) val = '';
                // Escape quotes and wrap in quotes if contains comma or newline
                const strVal = String(val);
                if (strVal.includes(',') || strVal.includes('"') || strVal.includes('\n')) {
                    return `"${strVal.replace(/"/g, '""')}"`;
                }
                return strVal;
            }).join(',');
        });

        const csvContent = [headers, ...rows].join('\n');
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.setAttribute('href', url);
        link.setAttribute('download', `${(title || 'export').replace(/\s+/g, '_').toLowerCase()}_${new Date().toISOString().slice(0, 10)}.csv`);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    return (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 overflow-visible mb-6 transition-colors duration-200 flex flex-col h-full max-h-[600px]">
            {title && (
                <div className="px-6 py-3 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center bg-gray-50 dark:bg-gray-800 shrink-0">
                    <h3 className="text-lg font-bold text-gray-900 dark:text-gray-100 uppercase tracking-wide text-xs">{title}</h3>
                    <div className="flex items-center gap-3">
                        <span className="px-2 py-0.5 rounded text-xs font-mono bg-gray-200 text-gray-800 dark:bg-gray-700 dark:text-gray-300">
                            {processedData.length} / {data.length} RECS
                        </span>
                        <button
                            onClick={downloadCSV}
                            className="text-xs flex items-center gap-1 px-2 py-1 bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-200 rounded transition-colors"
                            title="Export to CSV"
                        >
                            <Filter size={10} className="transform rotate-90" /> CSV
                        </button>
                    </div>
                </div>
            )}

            <div
                className="overflow-x-auto overflow-y-auto grow"
                ref={scrollContainerRef}
                onScroll={handleScroll}
            >
                <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700 relative">
                    <thead className="bg-gray-50 dark:bg-gray-900 sticky top-0 z-10 shadow-sm">
                        <tr>
                            {columns.map((col, idx) => (
                                <th
                                    key={idx}
                                    scope="col"
                                    className={`px-4 py-3 text-left text-xs font-bold text-gray-500 dark:text-gray-400 uppercase tracking-wider relative group select-none ${col.className || ''}`}
                                >
                                    <div className="flex items-center gap-2">
                                        {/* Sortable Header Text */}
                                        <div
                                            className={`flex items-center gap-1 cursor-pointer hover:text-gray-700 dark:hover:text-gray-200 ${sortConfig.key === col.accessor ? 'text-blue-600 dark:text-blue-400' : ''}`}
                                            onClick={() => col.accessor && handleSort(col.accessor)}
                                        >
                                            <span>{col.header}</span>
                                            {col.accessor && (
                                                <span className="opacity-0 group-hover:opacity-100 transition-opacity">
                                                    {sortConfig.key === col.accessor ? (
                                                        sortConfig.direction === 'asc' ? <ChevronUp size={12} /> : <ChevronDown size={12} />
                                                    ) : (
                                                        <ArrowUpDown size={12} />
                                                    )}
                                                </span>
                                            )}
                                            {/* Always show sort icon if active */}
                                            {col.accessor && sortConfig.key === col.accessor && (
                                                <span className="opacity-100">
                                                    {sortConfig.direction === 'asc' ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                                                </span>
                                            )}
                                        </div>

                                        {/* Filter Icon and Popover */}
                                        {col.accessor && (
                                            <div className="relative ml-auto">
                                                <button
                                                    onClick={(e) => { e.stopPropagation(); setActiveFilterCol(activeFilterCol === col.accessor ? null : col.accessor); }}
                                                    className={`p-1 rounded hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors ${filters[col.accessor] ? 'text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/30' : 'text-gray-400 opacity-0 group-hover:opacity-100'}`}
                                                >
                                                    <Filter size={12} />
                                                </button>

                                                {/* Filter Popup */}
                                                {activeFilterCol === col.accessor && (
                                                    <div className="absolute top-full right-0 mt-2 w-48 bg-white dark:bg-gray-800 rounded shadow-xl border border-gray-200 dark:border-gray-700 p-2 z-50" onClick={e => e.stopPropagation()}>
                                                        <div className="flex items-center gap-1 border border-gray-300 dark:border-gray-600 rounded px-2 py-1">
                                                            <input
                                                                type="text"
                                                                autoFocus
                                                                className="w-full text-xs bg-transparent border-none focus:outline-none text-gray-900 dark:text-white"
                                                                placeholder={`Filter ${col.header}...`}
                                                                value={filters[col.accessor] || ''}
                                                                onChange={(e) => handleFilterChange(col.accessor, e.target.value)}
                                                            />
                                                            {filters[col.accessor] && (
                                                                <button onClick={() => clearFilter(col.accessor)} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200">
                                                                    <X size={12} />
                                                                </button>
                                                            )}
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        )}
                                    </div>
                                </th>
                            ))}
                            {/* Actions Header Spacer */}
                            {actions && <th scope="col" className="px-4 py-3 bg-gray-50 dark:bg-gray-900"></th>}
                        </tr>
                    </thead>
                    <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700 font-mono text-xs">
                        {/* Top Spacer */}
                        {topPadding > 0 && (
                            <tr>
                                <td colSpan={columns.length + (actions ? 1 : 0)} style={{ height: `${topPadding}px` }} className="p-0 border-0"></td>
                            </tr>
                        )}

                        {processedData.length > 0 ? (
                            visibleData.map((row, idx) => (
                                <tr
                                    key={rowKey ? row[rowKey] : (startIndex + idx)}
                                    className={`transition-colors cursor-pointer group ${selectedRow === row ? 'bg-blue-50 dark:bg-blue-900/40 border-l-4 border-l-blue-500' : 'hover:bg-gray-50 dark:hover:bg-gray-700 border-l-4 border-l-transparent'
                                        }`}
                                    onClick={() => onRowClick && onRowClick(row)}
                                    style={{ height: `${ROW_HEIGHT}px` }}
                                >
                                    {columns.map((col, colIdx) => (
                                        <td key={colIdx} className={`px-4 py-1.5 whitespace-nowrap text-gray-700 dark:text-gray-300 border-r border-gray-100 dark:border-gray-700 last:border-r-0 ${col.className || ''}`}>
                                            {col.render ? col.render(row) : row[col.accessor]}
                                        </td>
                                    ))}
                                    {/* Actions Column (Implicit if actions prop provided) */}
                                    {actions && (
                                        <td className="px-4 py-1.5 whitespace-nowrap text-right border-l border-gray-100 dark:border-gray-700 sticky right-0 bg-white dark:bg-gray-800 group-hover:bg-gray-50 dark:group-hover:bg-gray-700 shadow-[-4px_0_8px_-4px_rgba(0,0,0,0.1)]">
                                            <div className="flex justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                                {actions(row)}
                                            </div>
                                        </td>
                                    )}
                                </tr>
                            ))
                        ) : (
                            <tr>
                                <td colSpan={columns.length + (actions ? 1 : 0)} className="px-6 py-8 text-center text-gray-500 dark:text-gray-400">
                                    No records match your filters.
                                </td>
                            </tr>
                        )}

                        {/* Bottom Spacer */}
                        {bottomPadding > 0 && (
                            <tr>
                                <td colSpan={columns.length + (actions ? 1 : 0)} style={{ height: `${bottomPadding}px` }} className="p-0 border-0"></td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default DataTable;
