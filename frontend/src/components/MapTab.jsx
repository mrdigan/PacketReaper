import React, { useMemo, useState } from 'react';
import { ComposableMap, Geographies, Geography, Marker, ZoomableGroup } from "react-simple-maps";
import { scaleLinear } from "d3-scale";

// Import the local TopoJSON file
import geoUrl from '../assets/world-110m.json';

const MapTab = ({ result }) => {
    const hosts = result?.hosts || [];

    // Filter hosts with valid coordinates
    const locatedHosts = useMemo(() => {
        return hosts.filter(h => h.latitude && h.longitude && (h.latitude !== 0 || h.longitude !== 0));
    }, [hosts]);

    // Scaling for marker size based on packet count
    const maxPackets = Math.max(...locatedHosts.map(h => h.packets_sent + h.packets_received), 0);
    const sizeScale = scaleLinear()
        .domain([0, maxPackets])
        .range([4, 12]); // Min 4px, Max 12px

    const [tooltip, setTooltip] = useState(null);

    return (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6 h-full flex flex-col">
            <div className="flex justify-between items-center mb-4">
                <h3 className="text-xl font-bold text-gray-900 dark:text-white">Global Host Distribution</h3>
                <div className="flex items-center gap-4 bg-gray-100 dark:bg-gray-900 px-4 py-2 rounded-lg border border-gray-200 dark:border-gray-700">
                    <div className="text-sm">
                        <span className="text-gray-500 dark:text-gray-400">Located Hosts: </span>
                        <span className="font-bold text-cyan-600 dark:text-cyan-400">{locatedHosts.length}</span>
                        <span className="text-xs text-gray-400 ml-1">/ {hosts.length}</span>
                    </div>
                </div>
            </div>

            <div className="flex-1 relative bg-gray-50 dark:bg-gray-900 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                <ComposableMap
                    projection="geoMercator"
                    projectionConfig={{
                        scale: 120, // Adjust zoom level
                    }}
                    style={{ width: "100%", height: "100%" }}
                >
                    <ZoomableGroup center={[0, 20]} zoom={1}>
                        {/* Map Geographies */}
                        <Geographies geography={geoUrl}>
                            {({ geographies }) =>
                                geographies.map((geo) => (
                                    <Geography
                                        key={geo.rsmKey}
                                        geography={geo}
                                        fill="#D6D6DA"
                                        stroke="#FFFFFF"
                                        strokeWidth={0.5}
                                        style={{
                                            default: { fill: "#374151" }, // dark-gray-700
                                            hover: { fill: "#4B5563" },   // dark-gray-600
                                            pressed: { fill: "#1F2937" }, // dark-gray-800
                                        }}
                                        className="transition-colors duration-200 outline-none"
                                    />
                                ))
                            }
                        </Geographies>

                        {/* Markers */}
                        {locatedHosts.map((host, idx) => {
                            const size = sizeScale(host.packets_sent + host.packets_received);
                            return (
                                <Marker
                                    key={idx}
                                    coordinates={[host.longitude, host.latitude]}
                                    onMouseEnter={(e) => {
                                        // Use page coordinates for tooltip to avoid ZoomableGroup scaling issues
                                        const { clientX, clientY } = window.event || e;
                                        setTooltip({
                                            x: clientX,
                                            y: clientY,
                                            host: host
                                        });
                                    }}
                                    onMouseLeave={() => setTooltip(null)}
                                >
                                    <circle
                                        r={size}
                                        fill="#06B6D4" // text-cyan-500
                                        stroke="#FFFFFF"
                                        strokeWidth={1.5}
                                        className="cursor-pointer opacity-80 hover:opacity-100 hover:fill-cyan-300 transition-all duration-200"
                                    />
                                </Marker>
                            );
                        })}
                    </ZoomableGroup>
                </ComposableMap>

                {/* Tooltip */}
                {tooltip && (
                    <div
                        className="fixed z-50 bg-gray-900 text-white text-xs rounded-lg py-2 px-3 shadow-xl pointer-events-none transform -translate-x-1/2 -translate-y-full mt-[-15px]"
                        style={{ left: tooltip.x, top: tooltip.y }}
                    >
                        <div className="font-bold mb-1 text-cyan-300">{tooltip.host.ip}</div>
                        <div className="flex flex-col gap-0.5 text-gray-300">
                            <span>{tooltip.host.city || 'Unknown City'}, {tooltip.host.country || 'Unknown Country'}</span>
                            {tooltip.host.organization && (
                                <span className="italic opacity-80 truncate max-w-[200px]">{tooltip.host.organization}</span>
                            )}
                        </div>
                        <div className="mt-2 flex gap-2 border-t border-gray-700 pt-1">
                            <span className="bg-green-900/50 text-green-200 px-1.5 rounded">↑ {tooltip.host.packets_sent}</span>
                            <span className="bg-blue-900/50 text-blue-200 px-1.5 rounded">↓ {tooltip.host.packets_received}</span>
                        </div>
                    </div>
                )}
            </div>

            <div className="mt-4 text-xs text-center text-gray-400">
                Offline Map Data | Drag to Pan | Scroll to Zoom
            </div>
        </div>
    );
};

export default MapTab;
