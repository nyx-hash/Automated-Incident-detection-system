import React, { useState, useEffect } from 'react';
import { 
  Play, 
  Pause, 
  Square, 
  HelpCircle,
  Wifi,
  Bot,
  Shield,
  AlertTriangle
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { 
  SimulationStatus, 
  SimulationAttackType, 
  SimulationMode
} from '@/types';
import { useToast } from '@/hooks/use-toast';
import { apiRequest } from '@/lib/queryClient';

export function SimulationControls() {
  const [status, setStatus] = useState<SimulationStatus>('idle');
  const [attackType, setAttackType] = useState<SimulationAttackType>('ddos');
  const [mode, setMode] = useState<SimulationMode>('real');
  const { toast } = useToast();
  
  useEffect(() => {
    // Start real monitoring by default when component mounts
    handleModeChange('real');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  
  const handleStart = async () => {
    try {
      const response = await apiRequest('/api/simulate', {
        method: 'POST',
        body: JSON.stringify({
          action: 'start',
          mode,
          type: mode === 'attack' ? attackType : undefined
        })
      });
      
      if (response.ok) {
        setStatus('running');
        const data = await response.json();
        toast({
          title: "Monitoring Started",
          description: `${mode === 'real' ? 'Real-time monitoring' : 
                        mode === 'simulated' ? 'Simulated traffic' : 
                        `${attackType} attack simulation`} has been started.`,
        });
      }
    } catch (error) {
      console.error('Failed to start monitoring/simulation:', error);
      toast({
        title: "Error",
        description: "Failed to start monitoring. Please try again.",
        variant: "destructive"
      });
    }
  };
  
  const handlePause = () => {
    setStatus(status === 'running' ? 'paused' : 'running');
    // For now, we don't have a pause API, just UI state
  };
  
  const handleStop = async () => {
    try {
      const response = await apiRequest('/api/simulate', {
        method: 'POST',
        body: JSON.stringify({
          action: 'stop',
          mode
        })
      });
      
      if (response.ok) {
        setStatus('idle');
        toast({
          title: "Monitoring Stopped",
          description: `${mode === 'real' ? 'Real-time monitoring' : 
                        mode === 'simulated' ? 'Simulated traffic' : 
                        `${attackType} attack simulation`} has been stopped.`,
        });
      }
    } catch (error) {
      console.error('Failed to stop monitoring/simulation:', error);
      toast({
        title: "Error",
        description: "Failed to stop monitoring. Please try again.",
        variant: "destructive"
      });
    }
  };
  
  const handleAttackTypeChange = (value: string) => {
    setAttackType(value as SimulationAttackType);
    if (status === 'running' && mode === 'attack') {
      // If already running in attack mode, restart with new attack type
      handleStop().then(() => {
        setMode('attack');
        handleStart();
      });
    }
  };
  
  const handleModeChange = async (newMode: SimulationMode) => {
    // If currently running, stop before changing mode
    if (status === 'running') {
      await handleStop();
    }
    
    setMode(newMode);
    toast({
      title: "Mode Changed",
      description: `Switched to ${newMode === 'real' ? 'real-time monitoring' : 
                    newMode === 'simulated' ? 'simulated traffic' : 
                    'attack simulation'} mode.`,
    });
    
    // Auto-start in the new mode
    if (newMode === 'real') {
      setTimeout(() => handleStart(), 500);
    }
  };
  
  return (
    <div className="fixed bottom-4 right-4 z-50">
      <div className="bg-background rounded-lg shadow-lg p-3 border border-border max-w-xs">
        <div className="flex items-center mb-2">
          <h3 className="text-sm font-bold">Network Monitoring</h3>
          <Button variant="ghost" size="icon" className="ml-3 h-5 w-5">
            <HelpCircle className="h-4 w-4 text-muted-foreground" />
          </Button>
        </div>
        
        <div className="flex space-x-2 mb-2">
          <Button
            variant={mode === 'real' ? 'default' : 'outline'}
            onClick={() => handleModeChange('real')}
            size="sm"
            className="h-8 text-xs flex-1"
          >
            <Wifi className="h-3 w-3 mr-1" />
            Real
          </Button>
          <Button
            variant={mode === 'simulated' ? 'default' : 'outline'}
            onClick={() => handleModeChange('simulated')}
            size="sm"
            className="h-8 text-xs flex-1"
          >
            <Bot className="h-3 w-3 mr-1" />
            Simulated
          </Button>
          <Button
            variant={mode === 'attack' ? 'default' : 'outline'}
            onClick={() => handleModeChange('attack')}
            size="sm"
            className="h-8 text-xs flex-1"
          >
            <AlertTriangle className="h-3 w-3 mr-1" />
            Attack
          </Button>
        </div>
        
        <div className="flex space-x-2">
          <Button
            size="icon"
            variant={status === 'running' ? 'default' : 'secondary'}
            onClick={handleStart}
            disabled={status === 'running'}
            className="h-8 w-8"
          >
            <Play className="h-4 w-4" />
          </Button>
          <Button
            size="icon"
            variant="secondary"
            onClick={handleStop}
            disabled={status === 'idle'}
            className="h-8 w-8"
          >
            <Square className="h-4 w-4" />
          </Button>
          
          {mode === 'attack' && (
            <Select value={attackType} onValueChange={handleAttackTypeChange}>
              <SelectTrigger className="w-[150px] h-8 text-xs">
                <SelectValue placeholder="Select attack type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ddos">DoS/DDoS Attack</SelectItem>
                <SelectItem value="port_scan">Port Scan</SelectItem>
                <SelectItem value="brute_force">Brute Force</SelectItem>
                <SelectItem value="data_exfiltration">Data Exfiltration</SelectItem>
                <SelectItem value="malware_communication">Malware C2</SelectItem>
              </SelectContent>
            </Select>
          )}
        </div>
        
        {status === 'running' && (
          <div className="mt-2 text-xs text-[hsl(var(--alert-medium))]">
            {mode === 'real' ? 'Monitoring real network traffic' :
             mode === 'simulated' ? 'Simulating network traffic' :
             `Simulating ${attackType.replace('_', ' ')} attack...`}
          </div>
        )}
        
        {status === 'idle' && (
          <div className="mt-2 text-xs text-muted-foreground">
            {mode === 'real' ? 'Real-time monitoring ready' :
             mode === 'simulated' ? 'Traffic simulation ready' :
             'Attack simulation ready'}
          </div>
        )}
      </div>
    </div>
  );
}
