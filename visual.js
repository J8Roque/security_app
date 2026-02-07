// visualizations.js - Data visualizations for cybersecurity dashboard

class SecurityVisualizations {
    // Threat Map Visualization
    static initThreatMap() {
        const canvas = document.getElementById('threatCanvas');
        if (!canvas) return;
        
        const ctx = canvas.getContext('2d');
        const width = canvas.width;
        const height = canvas.height;
        
        // World map coordinates (simplified)
        const locations = [
            { x: width * 0.25, y: height * 0.3, country: 'US', threats: 15 },
            { x: width * 0.7, y: height * 0.3, country: 'CN', threats: 12 },
            { x: width * 0.5, y: height * 0.2, country: 'RU', threats: 8 },
            { x: width * 0.45, y: height * 0.4, country: 'EU', threats: 6 },
            { x: width * 0.8, y: height * 0.5, country: 'JP', threats: 4 },
            { x: width * 0.65, y: height * 0.6, country: 'IN', threats: 7 },
            { x: width * 0.3, y: height * 0.7, country: 'BR', threats: 3 },
            { x: width * 0.4, y: height * 0.3, country: 'UK', threats: 5 }
        ];
        
        // Draw connections between locations
        ctx.clearRect(0, 0, width, height);
        
        // Draw network lines
        ctx.strokeStyle = 'rgba(100, 255, 218, 0.2)';
        ctx.lineWidth = 1;
        
        locations.forEach((loc1, i) => {
            locations.forEach((loc2, j) => {
                if (i < j && Math.random() > 0.7) {
                    ctx.beginPath();
                    ctx.moveTo(loc1.x, loc1.y);
                    ctx.lineTo(loc2.x, loc2.y);
                    ctx.stroke();
                }
            });
        });
        
        // Draw threat locations
        locations.forEach(location => {
            // Draw threat pulses
            ctx.beginPath();
            ctx.arc(location.x, location.y, location.threats * 2, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(255, 46, 99, ${0.1 + location.threats * 0.05})`;
            ctx.fill();
            
            // Draw threat center
            ctx.beginPath();
            ctx.arc(location.x, location.y, 5, 0, Math.PI * 2);
            ctx.fillStyle = location.threats > 10 ? '#ff2e63' : 
                           location.threats > 5 ? '#ff6b6b' : '#ffd166';
            ctx.fill();
            ctx.strokeStyle = 'rgba(255, 255, 255, 0.8)';
            ctx.lineWidth = 2;
            ctx.stroke();
            
            // Draw country label
            ctx.fillStyle = '#e6f1ff';
            ctx.font = '12px Inter';
            ctx.textAlign = 'center';
            ctx.fillText(location.country, location.x, location.y - 15);
            
            // Draw threat count
            ctx.fillStyle = location.threats > 10 ? '#ff2e63' : 
                           location.threats > 5 ? '#ff6b6b' : '#ffd166';
            ctx.font = '10px JetBrains Mono';
            ctx.fillText(location.threats, location.x, location.y + 25);
        });
        
        // Animate the threat map
        requestAnimationFrame(() => {
            this.animateThreatMap(ctx, width, height, locations);
        });
    }
    
    static animateThreatMap(ctx, width, height, locations) {
        // Draw animated pulses
        locations.forEach(location => {
            const pulseSize = (Date.now() * 0.002) % 20;
            
            ctx.beginPath();
            ctx.arc(location.x, location.y, pulseSize, 0, Math.PI * 2);
            ctx.strokeStyle = `rgba(255, 46, 99, ${0.3 - pulseSize * 0.015})`;
            ctx.lineWidth = 2;
            ctx.stroke();
        });
        
        requestAnimationFrame(() => {
            ctx.clearRect(0, 0, width, height);
            this.initThreatMap(); // Redraw everything
        });
    }
    
    // Network Traffic Visualization
    static initNetworkTraffic() {
        const canvas = document.getElementById('networkCanvas');
        if (!canvas) return;
        
        const ctx = canvas.getContext('2d');
        const width = canvas.width = canvas.parentElement.clientWidth;
        const height = canvas.height = 400;
        
        // Network nodes
        const nodes = [
            { x: width * 0.2, y: height * 0.5, type: 'server', label: 'Main Server', traffic: 120 },
            { x: width * 0.8, y: height * 0.5, type: 'cloud', label: 'Cloud Storage', traffic: 80 },
            { x: width * 0.5, y: height * 0.2, type: 'router', label: 'Router', traffic: 200 },
            { x: width * 0.3, y: height * 0.8, type: 'workstation', label: 'Workstation', traffic: 40 },
            { x: width * 0.7, y: height * 0.8, type: 'workstation', label: 'Workstation', traffic: 60 },
            { x: width * 0.5, y: height * 0.7, type: 'firewall', label: 'Firewall', traffic: 180 }
        ];
        
        // Draw network connections
        const drawConnections = () => {
            ctx.clearRect(0, 0, width, height);
            
            // Draw connections
            nodes.forEach((node1, i) => {
                nodes.forEach((node2, j) => {
                    if (i < j && Math.random() > 0.5) {
                        const distance = Math.sqrt(
                            Math.pow(node2.x - node1.x, 2) + 
                            Math.pow(node2.y - node1.y, 2)
                        );
                        
                        // Draw animated data packets
                        const progress = (Date.now() * 0.001) % 1;
                        const packetX = node1.x + (node2.x - node1.x) * progress;
                        const packetY = node1.y + (node2.y - node1.y) * progress;
                        
                        // Draw connection line
                        ctx.beginPath();
                        ctx.moveTo(node1.x, node1.y);
                        ctx.lineTo(node2.x, node2.y);
                        ctx.strokeStyle = 'rgba(100, 255, 218, 0.1)';
                        ctx.lineWidth = 1;
                        ctx.stroke();
                        
                        // Draw data packet
                        ctx.beginPath();
                        ctx.arc(packetX, packetY, 3, 0, Math.PI * 2);
                        ctx.fillStyle = '#64ffda';
                        ctx.fill();
                    }
                });
            });
            
            // Draw nodes
            nodes.forEach(node => {
                // Draw node
                ctx.beginPath();
                ctx.arc(node.x, node.y, 15, 0, Math.PI * 2);
                
                switch(node.type) {
                    case 'server':
                        ctx.fillStyle = '#ff2e63';
                        break;
                    case 'cloud':
                        ctx.fillStyle = '#9d4edd';
                        break;
                    case 'router':
                        ctx.fillStyle = '#64ffda';
                        break;
                    case 'firewall':
                        ctx.fillStyle = '#ffd166';
                        break;
                    default:
                        ctx.fillStyle = '#4ecdc4';
                }
                
                ctx.fill();
                ctx.strokeStyle = 'rgba(255, 255, 255, 0.8)';
                ctx.lineWidth = 2;
                ctx.stroke();
                
                // Draw node label
                ctx.fillStyle = '#e6f1ff';
                ctx.font = '10px Inter';
                ctx.textAlign = 'center';
                ctx.fillText(node.label, node.x, node.y - 25);
                
                // Draw traffic indicator
                ctx.beginPath();
                ctx.arc(node.x, node.y, 20, -Math.PI/2, -Math.PI/2 + (node.traffic/250) * Math.PI * 2);
                ctx.strokeStyle = '#00ff88';
                ctx.lineWidth = 3;
                ctx.stroke();
            });
        };
        
        // Animate network
        const animate = () => {
            drawConnections();
            requestAnimationFrame(animate);
        };
        
        animate();
    }
    
    // Vulnerability Chart
    static createVulnerabilityChart(vulnerabilities) {
        const severityCounts = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        };
        
        vulnerabilities.forEach(vuln => {
            severityCounts[vuln.severity] = (severityCounts[vuln.severity] || 0) + 1;
        });
        
        // Create chart canvas
        let chartCanvas = document.getElementById('vulnerabilityChart');
        if (!chartCanvas) {
            chartCanvas = document.createElement('canvas');
            chartCanvas.id = 'vulnerabilityChart';
            chartCanvas.width = 300;
            chartCanvas.height = 300;
            document.querySelector('.scan-results')?.appendChild(chartCanvas);
        }
        
        const ctx = chartCanvas.getContext('2d');
        const centerX = chartCanvas.width / 2;
        const centerY = chartCanvas.height / 2;
        const radius = Math.min(centerX, centerY) - 10;
        
        const colors = {
            critical: '#ff2e63',
            high: '#ff6b6b',
            medium: '#ffd166',
            low: '#4ecdc4'
        };
        
        const total = Object.values(severityCounts).reduce((a, b) => a + b, 0);
        
        if (total === 0) {
            ctx.clearRect(0, 0, chartCanvas.width, chartCanvas.height);
            ctx.fillStyle = '#8892b0';
            ctx.font = '14px Inter';
            ctx.textAlign = 'center';
            ctx.fillText('No vulnerabilities found', centerX, centerY);
            return;
        }
        
        let startAngle = 0;
        
        Object.entries(severityCounts).forEach(([severity, count]) => {
            if (count === 0) return;
            
            const sliceAngle = (count / total) * 2 * Math.PI;
            
            // Draw slice
            ctx.beginPath();
            ctx.moveTo(centerX, centerY);
            ctx.arc(centerX, centerY, radius, startAngle, startAngle + sliceAngle);
            ctx.closePath();
            ctx.fillStyle = colors[severity];
            ctx.fill();
            
            // Draw label
            const midAngle = startAngle + sliceAngle / 2;
            const labelX = centerX + (radius * 0.7) * Math.cos(midAngle);
            const labelY = centerY + (radius * 0.7) * Math.sin(midAngle);
            
            ctx.fillStyle = '#e6f1ff';
            ctx.font = '10px Inter';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText(`${severity.toUpperCase()}: ${count}`, labelX, labelY);
            
            startAngle += sliceAngle;
        });
        
        // Draw center hole
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius * 0.5, 0, Math.PI * 2);
        ctx.fillStyle = '#0a192f';
        ctx.fill();
        
        // Draw total in center
        ctx.fillStyle = '#64ffda';
        ctx.font = 'bold 20px JetBrains Mono';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(total.toString(), centerX, centerY);
        
        ctx.fillStyle = '#a8b2d1';
        ctx.font = '10px Inter';
        ctx.fillText('Total Vulns', centerX, centerY + 20);
    }
    
    // Password Strength Visualization
    static updatePasswordStrength(password) {
        const strength = SecurityUtils.calculatePasswordStrength(password);
        const fill = document.getElementById('strengthFill');
        const feedback = document.getElementById('passwordFeedback');
        
        if (fill) {
            fill.style.width = `${strength.score}%`;
            fill.style.background = this.getStrengthColor(strength.score);
        }
        
        if (feedback) {
            feedback.innerHTML = `
                <div class="feedback-item ${strength.score >= 90 ? 'valid' : 'invalid'}">
                    <i class="fas ${strength.score >= 90 ? 'fa-check-circle' : 'fa-times-circle'}"></i>
                    <span>Strength: ${strength.strength}</span>
                </div>
                ${strength.feedback.map(item => `
                    <div class="feedback-item invalid">
                        <i class="fas fa-exclamation-circle"></i>
                        <span>${item}</span>
                    </div>
                `).join('')}
            `;
        }
        
        // Update metrics
        document.getElementById('lengthScore')?.textContent = `${password.length}/12`;
        document.getElementById('complexityScore')?.textContent = `${this.calculateComplexityScore(password)}/5`;
        document.getElementById('entropyScore')?.textContent = `${Math.round(SecurityUtils.calculateEntropy(password))} bits`;
    }
    
    static calculateComplexityScore(password) {
        let score = 0;
        if (/[a-z]/.test(password)) score++;
        if (/[A-Z]/.test(password)) score++;
        if (/[0-9]/.test(password)) score++;
        if (/[^A-Za-z0-9]/.test(password)) score++;
        if (password.length >= 12) score++;
        return score;
    }
    
    static getStrengthColor(score) {
        if (score >= 90) return 'linear-gradient(90deg, #00ff88, #00cc66)';
        if (score >= 70) return 'linear-gradient(90deg, #00cc66, #ffd166)';
        if (score >= 50) return 'linear-gradient(90deg, #ffd166, #ffaa00)';
        if (score >= 30) return 'linear-gradient(90deg, #ffaa00, #ff6b6b)';
        return 'linear-gradient(90deg, #ff6b6b, #ff2e63)';
    }
    
    // Real-time Metrics Chart
    static createMetricsChart() {
        const canvas = document.getElementById('metricsChart');
        if (!canvas) return;
        
        const ctx = canvas.getContext('2d');
        const width = canvas.width;
        const height = canvas.height;
        
        // Simulated metrics data
        const metrics = {
            cpu: Array.from({ length: 20 }, () => Math.random() * 100),
            memory: Array.from({ length: 20 }, () => 30 + Math.random() * 50),
            network: Array.from({ length: 20 }, () => Math.random() * 100),
            threats: Array.from({ length: 20 }, () => Math.random() * 10)
        };
        
        const drawLine = (data, color, yScale) => {
            ctx.beginPath();
            ctx.strokeStyle = color;
            ctx.lineWidth = 2;
            
            const xStep = width / (data.length - 1);
            
            data.forEach((value, index) => {
                const x = index * xStep;
                const y = height - (value * yScale);
                
                if (index === 0) {
                    ctx.moveTo(x, y);
                } else {
                    ctx.lineTo(x, y);
                }
            });
            
            ctx.stroke();
            
            // Fill under line
            ctx.lineTo(width, height);
            ctx.lineTo(0, height);
            ctx.closePath();
            ctx.fillStyle = color + '20';
            ctx.fill();
        };
        
        ctx.clearRect(0, 0, width, height);
        
        // Draw grid
        ctx.strokeStyle = 'rgba(100, 255, 218, 0.1)';
        ctx.lineWidth = 1;
        
        for (let i = 0; i <= 5; i++) {
            const y = (i / 5) * height;
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(width, y);
            ctx.stroke();
            
            ctx.fillStyle = '#8892b0';
            ctx.font = '10px Inter';
            ctx.fillText(`${100 - i * 20}%`, width - 30, y - 5);
        }
        
        // Draw metric lines
        drawLine(metrics.cpu, '#ff2e63', height / 100);
        drawLine(metrics.memory, '#64ffda', height / 100);
        drawLine(metrics.network, '#9d4edd', height / 100);
        drawLine(metrics.threats, '#ffd166', height / 10);
        
        // Draw legend
        const legend = [
            { label: 'CPU Usage', color: '#ff2e63' },
            { label: 'Memory', color: '#64ffda' },
            { label: 'Network', color: '#9d4edd' },
            { label: 'Threats', color: '#ffd166' }
        ];
        
        legend.forEach((item, index) => {
            ctx.fillStyle = item.color;
            ctx.font = '10px Inter';
            ctx.fillText(item.label, 10, 20 + index * 15);
        });
    }
    
    // Initialize all visualizations
    static initAllVisualizations() {
        this.initThreatMap();
        this.initNetworkTraffic();
        
        // Update visualizations periodically
        setInterval(() => {
            this.initThreatMap();
            this.createMetricsChart();
        }, 5000);
        
        // Handle window resize
        window.addEventListener('resize', () => {
            this.initNetworkTraffic();
        });
    }
}

// Initialize visualizations when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    setTimeout(() => {
        SecurityVisualizations.initAllVisualizations();
    }, 1000);
});

// Export for global use
window.SecurityVisualizations = SecurityVisualizations;
