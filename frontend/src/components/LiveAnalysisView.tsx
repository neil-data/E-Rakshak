/**
 * LiveAnalysisView — Real-time malware analysis dashboard
 *
 * Features:
 * - Live event stream from sandbox
 * - Real-time risk scoring with band visualization
 * - Active alerts panel
 * - Process tree
 * - IOC extraction and geolocation
 * - Investigator controls (pause/resume/kill)
 */

import React, { useEffect, useState, useRef, useCallback } from 'react';
import { useParams } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { AlertCircle, Play, Pause, X, TrendingUp, TrendingDown } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import useStore from '@/store';
import '@/styles/live-monitoring.css';

interface LiveAnalysisViewProps {
  analysisId: string;
}

interface Event {
  event_id: string;
  timestamp: string;
  event_type: 'file' | 'network' | 'api' | 'registry' | 'process';
  event_data: Record<string, any>;
  enrichment?: Record<string, any>;
  mitre_techniques: string[];
  severity?: string;
}

interface RiskScoreUpdate {
  score: number;
  reasoning: string;
  signal_breakdown: Record<string, any>;
  trend: 'increasing' | 'decreasing' | 'stable';
  timestamp: string;
}

interface AlertData {
  alert_id: string;
  rule_id: string;
  severity: 'info' | 'warning' | 'critical';
  message: string;
  mitre_techniques: string[];
  timestamp: string;
  dismissed: boolean;
}

interface IOCData {
  ioc_id: string;
  ioc_type: string;
  ioc_value: string;
  confidence: number;
  first_seen: string;
  threat_intel?: Record<string, any>;
}

const LiveAnalysisView: React.FC<LiveAnalysisViewProps> = ({ analysisId }) => {
  const [websocket, setWebsocket] = useState<WebSocket | null>(null);
  const [events, setEvents] = useState<Event[]>([]);
  const [riskScore, setRiskScore] = useState<RiskScoreUpdate | null>(null);
  const [alerts, setAlerts] = useState<AlertData[]>([]);
  const [iocs, setIOCs] = useState<IOCData[]>([]);
  const [riskHistory, setRiskHistory] = useState<Array<{ time: string; score: number }>>([]);
  const [connectionStatus, setConnectionStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting');
  const [sandboxStatus, setSandboxStatus] = useState<'running' | 'paused' | 'complete'>('running');
  const eventListRef = useRef<HTMLDivElement>(null);

  // Get JWT token (from localStorage or auth context)
  const token = localStorage.getItem('auth_token');

  useEffect(() => {
    connectWebSocket();

    return () => {
      if (websocket) {
        websocket.close();
      }
    };
  }, [analysisId, token]);

  const connectWebSocket = useCallback(() => {
    if (!token) return;

    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const wsUrl = `${protocol}://${window.location.host}/ws/${analysisId}?token=${token}`;

    try {
      const ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        console.log('WebSocket connected');
        setConnectionStatus('connected');
      };

      ws.onmessage = (event) => {
        handleWebSocketMessage(event.data);
      };

      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        setConnectionStatus('disconnected');
      };

      ws.onclose = () => {
        console.log('WebSocket closed');
        setConnectionStatus('disconnected');
        // Attempt reconnect after 3 seconds
        setTimeout(() => {
          if (connectionStatus !== 'connected') {
            connectWebSocket();
          }
        }, 3000);
      };

      setWebsocket(ws);
    } catch (error) {
      console.error('Failed to connect WebSocket:', error);
      setConnectionStatus('disconnected');
    }
  }, [analysisId, token, connectionStatus]);

  const handleWebSocketMessage = (data: string) => {
    try {
      const message = JSON.parse(data);

      switch (message.type) {
        case 'connected':
          console.log('Live monitoring connected');
          break;

        case 'event':
          addEvent(message.event);
          break;

        case 'risk_score':
          updateRiskScore(message);
          break;

        case 'alert':
          addAlert(message.alert);
          break;

        case 'ioc':
          addIOC(message.ioc);
          break;

        case 'status':
          setSandboxStatus(message.status);
          break;

        default:
          console.warn('Unknown message type:', message.type);
      }
    } catch (error) {
      console.error('Error parsing WebSocket message:', error);
    }
  };

  const addEvent = (event: Event) => {
    setEvents((prev) => {
      const updated = [event, ...prev];
      return updated.slice(0, 100); // Keep last 100 events
    });

    // Auto-scroll event list
    setTimeout(() => {
      eventListRef.current?.scrollTo(0, 0);
    }, 0);
  };

  const updateRiskScore = (update: RiskScoreUpdate) => {
    setRiskScore(update);

    // Add to history
    setRiskHistory((prev) => {
      const updated = [
        ...prev,
        {
          time: new Date(update.timestamp).toLocaleTimeString(),
          score: update.score,
        },
      ];
      return updated.slice(-30); // Keep last 30 points
    });
  };

  const addAlert = (alert: AlertData) => {
    setAlerts((prev) => {
      const updated = [alert, ...prev];
      return updated.slice(0, 20); // Keep last 20 alerts
    });
  };

  const addIOC = (ioc: IOCData) => {
    setIOCs((prev) => {
      const exists = prev.some((i) => i.ioc_value === ioc.ioc_value && i.ioc_type === ioc.ioc_type);
      if (exists) return prev;

      const updated = [ioc, ...prev];
      return updated.slice(0, 50); // Keep last 50 IOCs
    });
  };

  const handlePauseSandbox = async () => {
    try {
      const response = await fetch(`/api/analyses/${analysisId}/sandbox/control`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'pause' }),
      });

      if (response.ok) {
        setSandboxStatus('paused');
      }
    } catch (error) {
      console.error('Failed to pause sandbox:', error);
    }
  };

  const handleResumeSandbox = async () => {
    try {
      const response = await fetch(`/api/analyses/${analysisId}/sandbox/control`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'resume' }),
      });

      if (response.ok) {
        setSandboxStatus('running');
      }
    } catch (error) {
      console.error('Failed to resume sandbox:', error);
    }
  };

  const handleKillSandbox = async () => {
    if (!confirm('Are you sure you want to terminate the sandbox?')) return;

    try {
      const response = await fetch(`/api/analyses/${analysisId}/sandbox/control`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'kill' }),
      });

      if (response.ok) {
        setSandboxStatus('complete');
      }
    } catch (error) {
      console.error('Failed to kill sandbox:', error);
    }
  };

  const getRiskScoreBand = (score: number): 'green' | 'yellow' | 'orange' | 'red' => {
    if (score <= 30) return 'green';
    if (score <= 60) return 'yellow';
    if (score <= 85) return 'orange';
    return 'red';
  };

  const getRiskScoreColor = (band: string): string => {
    const colors = {
      green: '#10b981',
      yellow: '#f59e0b',
      orange: '#f97316',
      red: '#ef4444',
    };
    return colors[band as keyof typeof colors] || '#6b7280';
  };

  return (
    <div className="live-analysis-view">
      {/* Header */}
      <div className="live-header">
        <h1>Live Malware Analysis</h1>
        <div className="header-controls">
          <Badge
            variant={connectionStatus === 'connected' ? 'default' : 'destructive'}
          >
            {connectionStatus === 'connected' ? '🟢 Live' : '🔴 Disconnected'}
          </Badge>

          <div className="sandbox-controls">
            {sandboxStatus === 'running' && (
              <Button
                size="sm"
                variant="outline"
                onClick={handlePauseSandbox}
              >
                <Pause className="w-4 h-4 mr-2" />
                Pause
              </Button>
            )}

            {sandboxStatus === 'paused' && (
              <Button
                size="sm"
                variant="outline"
                onClick={handleResumeSandbox}
              >
                <Play className="w-4 h-4 mr-2" />
                Resume
              </Button>
            )}

            <Button
              size="sm"
              variant="destructive"
              onClick={handleKillSandbox}
              disabled={sandboxStatus === 'complete'}
            >
              <X className="w-4 h-4 mr-2" />
              Kill
            </Button>
          </div>
        </div>
      </div>

      <div className="live-content">
        {/* Left Panel: Risk Score & Alerts */}
        <div className="live-left-panel">
          {/* Risk Score Card */}
          <Card>
            <CardHeader>
              <CardTitle>Risk Score</CardTitle>
            </CardHeader>
            <CardContent>
              {riskScore ? (
                <>
                  <div className="risk-score-display">
                    <div
                      className={`risk-score-badge band-${getRiskScoreBand(riskScore.score)}`}
                      style={{ borderColor: getRiskScoreColor(getRiskScoreBand(riskScore.score)) }}
                    >
                      {riskScore.score}
                    </div>
                    <div className="risk-trend">
                      {riskScore.trend === 'increasing' && (
                        <TrendingUp className="w-5 h-5 text-red-500" />
                      )}
                      {riskScore.trend === 'decreasing' && (
                        <TrendingDown className="w-5 h-5 text-green-500" />
                      )}
                      <span>{riskScore.trend}</span>
                    </div>
                  </div>
                  <p className="risk-reasoning">{riskScore.reasoning}</p>
                  {riskHistory.length > 1 && (
                    <ResponsiveContainer width="100%" height={200}>
                      <LineChart data={riskHistory}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="time" />
                        <YAxis domain={[0, 100]} />
                        <Tooltip />
                        <Line
                          type="monotone"
                          dataKey="score"
                          stroke={getRiskScoreColor(
                            getRiskScoreBand(riskScore.score)
                          )}
                          isAnimationActive={false}
                        />
                      </LineChart>
                    </ResponsiveContainer>
                  )}
                </>
              ) : (
                <p>Calculating risk score...</p>
              )}
            </CardContent>
          </Card>

          {/* Alerts Card */}
          <Card>
            <CardHeader>
              <CardTitle>Active Alerts ({alerts.length})</CardTitle>
            </CardHeader>
            <CardContent className="alerts-list">
              {alerts.length === 0 ? (
                <p className="text-gray-500">No alerts yet</p>
              ) : (
                alerts.map((alert) => (
                  <Alert key={alert.alert_id} variant={alert.severity}>
                    <AlertCircle className="h-4 w-4" />
                    <AlertDescription>
                      <div className="alert-content">
                        <div className="alert-message">{alert.message}</div>
                        <div className="alert-meta">
                          <Badge variant="outline">{alert.rule_id}</Badge>
                          {alert.mitre_techniques.map((tech) => (
                            <Badge key={tech} variant="secondary">
                              {tech}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    </AlertDescription>
                  </Alert>
                ))
              )}
            </CardContent>
          </Card>
        </div>

        {/* Right Panel: Events & IOCs */}
        <div className="live-right-panel">
          {/* Events Card */}
          <Card>
            <CardHeader>
              <CardTitle>Live Events ({events.length})</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="events-list" ref={eventListRef}>
                {events.length === 0 ? (
                  <p className="text-gray-500">Waiting for events...</p>
                ) : (
                  events.map((event) => (
                    <div key={event.event_id} className="event-item">
                      <div className="event-header">
                        <Badge
                          variant={
                            event.severity === 'critical' ? 'destructive' : 'secondary'
                          }
                        >
                          {event.event_type}
                        </Badge>
                        <time className="text-xs text-gray-500">
                          {new Date(event.timestamp).toLocaleTimeString()}
                        </time>
                      </div>
                      <div className="event-data">
                        {event.event_type === 'network' && (
                          <p>
                            {event.event_data.src_ip}:{event.event_data.src_port} →{' '}
                            {event.event_data.dst_ip}:{event.event_data.dst_port}
                          </p>
                        )}
                        {event.event_type === 'file' && (
                          <p>{event.event_data.path}</p>
                        )}
                        {event.event_type === 'api' && (
                          <p>{event.event_data.api_name}</p>
                        )}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>

          {/* IOCs Card */}
          <Card>
            <CardHeader>
              <CardTitle>Extracted IOCs ({iocs.length})</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="iocs-list">
                {iocs.length === 0 ? (
                  <p className="text-gray-500">No IOCs extracted yet</p>
                ) : (
                  iocs.map((ioc) => (
                    <div key={ioc.ioc_id} className="ioc-item">
                      <div className="ioc-header">
                        <Badge>{ioc.ioc_type}</Badge>
                        <Badge
                          variant={
                            ioc.confidence > 80
                              ? 'destructive'
                              : ioc.confidence > 50
                              ? 'default'
                              : 'secondary'
                          }
                        >
                          {ioc.confidence}%
                        </Badge>
                      </div>
                      <div className="ioc-value">{ioc.ioc_value}</div>
                      {ioc.threat_intel?.known_c2 && (
                        <Badge variant="destructive">Known C2</Badge>
                      )}
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default LiveAnalysisView;
