import * as React from "react";
import {
  ReactFlow,
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  BackgroundVariant,
  NodeTypes,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

interface NetworkGraphProps {
  exfiltrationAnalysis: {
    data_types: string[];
    destinations: string[];
    timing_patterns: string;
    encryption_status: string;
    risk_assessment: string;
  } | null;
  victimImpact: {
    data_accessed: string[];
  } | null;
  malwareInfo: {
    name: string;
    type: string;
  };
}

// Custom node component
const CustomNode = ({ data }: { data: any }) => {
  const getNodeColor = () => {
    switch (data.type) {
      case "malware":
        return "bg-red-950/40 border-red-500";
      case "c2":
        return "bg-orange-950/40 border-orange-500";
      case "data":
        return "bg-yellow-950/40 border-yellow-500";
      case "victim":
        return "bg-blue-950/40 border-blue-500";
      default:
        return "bg-[#171717] border-[#222222]";
    }
  };

  const getIcon = () => {
    switch (data.type) {
      case "malware":
        return "🦠";
      case "c2":
        return "🌐";
      case "data":
        return "📊";
      case "victim":
        return "📱";
      default:
        return "📦";
    }
  };

  return (
    <div className={`px-4 py-2 rounded-lg border-2 ${getNodeColor()} min-w-[150px]`}>
      <div className="flex items-center space-x-2">
        <span className="text-xl">{getIcon()}</span>
        <div>
          <div className="font-semibold text-sm text-white">{data.label}</div>
          {data.subtitle && (
            <div className="text-xs text-[#A0A0A0]">{data.subtitle}</div>
          )}
        </div>
      </div>
    </div>
  );
};

const nodeTypes: NodeTypes = {
  custom: CustomNode,
};

export function NetworkGraph({
  exfiltrationAnalysis,
  victimImpact,
  malwareInfo,
}: NetworkGraphProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  React.useEffect(() => {
    if (!exfiltrationAnalysis) return;

    const newNodes: Node[] = [];
    const newEdges: Edge[] = [];
    let nodeId = 0;

    // Center point
    const centerX = 400;
    const centerY = 300;

    // Add victim device node (center-left)
    const victimNodeId = `node-${nodeId++}`;
    newNodes.push({
      id: victimNodeId,
      type: "custom",
      position: { x: centerX - 300, y: centerY },
      data: {
        label: "Victim Device",
        subtitle: malwareInfo.type,
        type: "victim",
      },
    });

    // Add malware node (center)
    const malwareNodeId = `node-${nodeId++}`;
    newNodes.push({
      id: malwareNodeId,
      type: "custom",
      position: { x: centerX - 100, y: centerY },
      data: {
        label: malwareInfo.name,
        subtitle: "Malware Sample",
        type: "malware",
      },
    });

    // Add edge from victim to malware
    newEdges.push({
      id: `edge-${victimNodeId}-${malwareNodeId}`,
      source: victimNodeId,
      target: malwareNodeId,
      label: "Infects",
      animated: true,
      style: { stroke: "#ef4444", strokeWidth: 2 },
    });

    // Add C2 server nodes (right side)
    exfiltrationAnalysis.destinations.forEach((dest, idx) => {
      const c2NodeId = `node-${nodeId++}`;
      const angle = (idx / exfiltrationAnalysis.destinations.length) * Math.PI * 2;
      const radius = 200;
      const x = centerX + 150 + Math.cos(angle) * radius;
      const y = centerY + Math.sin(angle) * radius * 0.6;

      newNodes.push({
        id: c2NodeId,
        type: "custom",
        position: { x, y },
        data: {
          label: dest,
          subtitle: "C2 Server",
          type: "c2",
        },
      });

      // Add edge from malware to C2
      newEdges.push({
        id: `edge-${malwareNodeId}-${c2NodeId}`,
        source: malwareNodeId,
        target: c2NodeId,
        label: exfiltrationAnalysis.timing_patterns,
        animated: true,
        style: { stroke: "#f97316", strokeWidth: 2 },
      });
    });

    // Add data type nodes (bottom)
    const dataTypes = [
      ...(victimImpact?.data_accessed || []),
      ...(exfiltrationAnalysis.data_types || []),
    ];
    const uniqueDataTypes = [...new Set(dataTypes)];

    uniqueDataTypes.forEach((dataType, idx) => {
      const dataNodeId = `node-${nodeId++}`;
      const x = centerX - 200 + (idx % 3) * 150;
      const y = centerY + 150 + Math.floor(idx / 3) * 100;

      newNodes.push({
        id: dataNodeId,
        type: "custom",
        position: { x, y },
        data: {
          label: dataType,
          subtitle: "Data Type",
          type: "data",
        },
      });

      // Add edge from victim to data type
      newEdges.push({
        id: `edge-${victimNodeId}-${dataNodeId}`,
        source: victimNodeId,
        target: dataNodeId,
        label: "Accesses",
        animated: true,
        style: { stroke: "#3b82f6", strokeWidth: 2 },
      });

      // Add edge from data type to C2 (exfiltration)
      exfiltrationAnalysis.destinations.forEach((dest, destIdx) => {
        const c2NodeId = `node-${2 + destIdx}`; // C2 nodes start at node-2
        newEdges.push({
          id: `edge-${dataNodeId}-${c2NodeId}`,
          source: dataNodeId,
          target: c2NodeId,
          label: exfiltrationAnalysis.encryption_status,
          animated: true,
          style: { stroke: "#eab308", strokeWidth: 1, strokeDasharray: "5,5" },
        });
      });
    });

    setNodes(newNodes);
    setEdges(newEdges);
  }, [exfiltrationAnalysis, victimImpact, malwareInfo, setNodes, setEdges]);

  if (!exfiltrationAnalysis) {
    return (
      <div className="bg-[#111111] border border-[#222222] rounded-lg p-8 text-center">
        <p className="text-[#6F6F6F]">No network analysis data available.</p>
      </div>
    );
  }

  return (
    <div className="w-full h-[500px] bg-[#0a0a0a] border border-[#222222] rounded-lg overflow-hidden">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        fitView
        colorMode="dark"
        attributionPosition="bottom-left"
      >
        <Background variant={BackgroundVariant.Dots} gap={24} size={1} color="#333333" />
        <Controls />
        <MiniMap
          nodeColor={(node) => {
            switch (node.data.type) {
              case "malware":
                return "#450a0a";
              case "c2":
                return "#431407";
              case "data":
                return "#422006";
              case "victim":
                return "#172554";
              default:
                return "#1f2937";
            }
          }}
          maskColor="rgba(0, 0, 0, 0.5)"
          bgColor="#111111"
        />
      </ReactFlow>
    </div>
  );
}
