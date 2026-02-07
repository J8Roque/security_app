// content.js - Core functionality and utilities

// Global data storage
let securityData = {
    threats: [],
    vulnerabilities: [],
    activities: [],
    metrics: {
        criticalThreats: 3,
        protectedSystems: 24,
        lastScan: '2h ago',
        networkTraffic: '1.2 GB'
    }
};

// Utility functions
function showLoading(show = true) {
    const loading = document.getElementById('loading');
    if (loading) {
        loading.style.display = show ? 'flex' : 'none';
    }
}

function showToast(message, type = 'info') {
    // Remove existing toasts
    const existingToasts = document.querySelectorAll('.toast');
    existingToasts.forEach(toast => toast.remove());
    
    // Create toast
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${type === 'error' ? '#ff2e63' : 
                     type === 'success' ? '#00ff88' : '#64ffda'};
        color: #0a192f;
        padding: 12px 24px;
        border-radius: 8px;
        z-index: 9999;
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(toast);
    
    // Add animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
        }
    `;
    document.head.appendChild(style);
    
    // Remove after 3 seconds
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function updateTime() {
    const now = new Date();
    const timeString = now.toLocaleTimeString('en-US', { 
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
    
    const timeElement = document.getElementById('current-time');
    if (timeElement) {
        timeElement.textContent = timeString;
    }
}

function addActivity(type, title, description) {
    const activity = {
        id: Date.now(),
        type,
        title,
        description,
        time: new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})
    };
    
    securityData.activities.unshift(activity);
    
    // Update UI
    updateActivityList();
    
    // Add to notifications
    showToast(title, type);
}

function updateActivityList() {
    const container = document.getElementById('activity-list');
    if (!container) return;
    
    container.innerHTML = '';
    
    securityData.activities.slice(0, 5).forEach(activity => {
        const item = document.createElement('div');
        item.className = 'activity-item';
        item.innerHTML = `
            <div class="activity-icon ${activity.type}">
                <i class="fas fa-${getActivityIcon(activity.type)}"></i>
            </div>
            <div class="activity-content">
                <div class="activity-title">${activity.title}</div>
                <div class="activity-desc">${activity.description}</div>
                <div class="activity-time">${activity.time}</div>
            </div>
        `;
        container.appendChild(item);
    });
}

function getActivityIcon(type) {
    const icons = {
        critical: 'exclamation-triangle',
        warning: 'exclamation-circle',
        info: 'info-circle',
        success: 'check-circle'
    };
    return icons[type] || 'info-circle';
}

// Password strength calculation
function calculatePasswordStrength(password) {
    if (!password) return 0;
    
    let score = 0;
    
    // Length
    if (password.length >= 8) score += 20;
    if (password.length >= 12) score += 10;
    if (password.length >= 16) score += 10;
    
    // Character variety
    if (/[a-z]/.test(password)) score += 10;
    if (/[A-Z]/.test(password)) score += 10;
    if (/[0-9]/.test(password)) score += 10;
    if (/[^A-Za-z0-9]/.test(password)) score += 10;
    
    // Common passwords check
    const commonPasswords = ['password', '123456', 'qwerty', 'admin', 'welcome'];
    if (!commonPasswords.includes(password.toLowerCase())) score += 10;
    
    return Math.min(100, score);
}

function updatePasswordStrengthVisual(password) {
    const strength = calculatePasswordStrength(password);
    const fill = document.getElementById('strength-fill');
    const feedback = document.getElementById('password-feedback');
    
    if (fill) {
        fill.style.width = `${strength}%`;
        
        // Update color
        if (strength < 40) {
            fill.style.background = '#ff2e63';
        } else if (strength < 70) {
            fill.style.background = '#ffd166';
        } else {
            fill.style.background = '#00ff88';
        }
    }
    
    if (feedback) {
        let feedbackText = '';
        if (strength < 40) {
            feedbackText = 'Weak password. Try adding uppercase letters, numbers, and symbols.';
        } else if (strength < 70) {
            feedbackText = 'Good password. Could be stronger with more variety.';
        } else {
            feedbackText = 'Strong password! Keep it safe.';
        }
        feedback.textContent = feedbackText;
    }
}

// Password generator
function generatePassword() {
    const length = parseInt(document.getElementById('length-slider').value) || 16;
    const uppercase = document.getElementById('uppercase').checked;
    const lowercase = document.getElementById('lowercase').checked;
    const numbers = document.getElementById('numbers').checked;
    const symbols = document.getElementById('symbols').checked;
    
    let charset = '';
    if (lowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (uppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (numbers) charset += '0123456789';
    if (symbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    // If no character types selected, use all
    if (!charset) charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    
    let password = '';
    for (let i = 0; i < length; i++) {
        password += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    
    // Ensure at least one of each selected type
    if (uppercase && !/[A-Z]/.test(password)) {
        password = password.slice(0, -1) + 'A';
    }
    if (lowercase && !/[a-z]/.test(password)) {
        password = password.slice(0, -1) + 'a';
    }
    if (numbers && !/[0-9]/.test(password)) {
        password = password.slice(0, -1) + '1';
    }
    if (symbols && !/[^A-Za-z0-9]/.test(password)) {
        password = password.slice(0, -1) + '!';
    }
    
    document.getElementById('generated-password').value = password;
    updatePasswordStrengthVisual(password);
    showToast('Password generated successfully!', 'success');
}

function copyPassword() {
    const password = document.getElementById('generated-password').value;
    if (!password) {
        showToast('Generate a password first', 'error');
        return;
    }
    
    navigator.clipboard.writeText(password).then(() => {
        showToast('Password copied to clipboard!', 'success');
    });
}

function togglePassword() {
    const input = document.getElementById('password-input');
    const button = document.querySelector('.btn-eye i');
    
    if (input.type === 'password') {
        input.type = 'text';
        button.className = 'fas fa-eye-slash';
    } else {
        input.type = 'password';
        button.className = 'fas fa-eye';
    }
}

// Scanner functions
function startScan() {
    const target = document.getElementById('scan-target').value;
    const scanType = document.getElementById('scan-type').value;
    
    if (!target) {
        showToast('Please enter a target to scan', 'error');
        return;
    }
    
    showLoading(true);
    
    // Simulate scanning
    setTimeout(() => {
        showLoading(false);
        
        // Generate random vulnerabilities
        const vulnerabilities = generateVulnerabilities(target, scanType);
        displayVulnerabilities(vulnerabilities);
        
        addActivity('info', 'Scan Complete', `Scanned ${target} - Found ${vulnerabilities.length} vulnerabilities`);
        showToast(`Scan complete! Found ${vulnerabilities.length} vulnerabilities`, 'success');
    }, 2000);
}

function generateVulnerabilities(target, scanType) {
    const vulns = [
        {
            title: 'Outdated Software Version',
            severity: 'critical',
            description: `Running outdated version on ${target} with known security vulnerabilities`,
            remediation: 'Update to the latest version immediately'
        },
        {
            title: 'Weak SSL/TLS Configuration',
            severity: 'high',
            description: 'Using weak cipher suites and outdated TLS versions',
            remediation: 'Update TLS configuration and disable weak ciphers'
        },
        {
            title: 'Open Port Vulnerabilities',
            severity: 'high',
            description: 'Multiple unnecessary ports open to public access',
            remediation: 'Close unused ports and restrict access'
        },
        {
            title: 'SQL Injection Vulnerability',
            severity: 'critical',
            description: 'Input fields vulnerable to SQL injection attacks',
            remediation: 'Implement parameterized queries and input validation'
        },
        {
            title: 'Cross-Site Scripting (XSS)',
            severity: 'medium',
            description: 'User input not properly sanitized',
            remediation: 'Implement proper input sanitization'
        }
    ];
    
    // Return random number of vulnerabilities based on scan type
    const count = scanType === 'full' ? 4 : scanType === 'port' ? 2 : 3;
    return vulns.slice(0, count).map(vuln => ({
        ...vuln,
        id: Date.now() + Math.random()
    }));
}

function displayVulnerabilities(vulnerabilities) {
    const container = document.getElementById('vulnerabilities');
    if (!container) return;
    
    // Count by severity
    const counts = { critical: 0, high: 0, medium: 0 };
    
    container.innerHTML = '';
    vulnerabilities.forEach(vuln => {
        counts[vuln.severity] = (counts[vuln.severity] || 0) + 1;
        
        const item = document.createElement('div');
        item.className = `vulnerability-item ${vuln.severity}`;
        item.innerHTML = `
            <h4>${vuln.title}</h4>
            <p>${vuln.description}</p>
            <div class="remediation">
                <strong>Fix:</strong> ${vuln.remediation}
            </div>
        `;
        container.appendChild(item);
    });
    
    // Update counts
    document.getElementById('crit-count').textContent = counts.critical;
    document.getElementById('high-count').textContent = counts.high;
    document.getElementById('med-count').textContent = counts.medium;
}

// Threat functions
function loadThreats() {
    const threats = [
        {
            id: 1,
            title: 'Advanced Persistent Threat',
            severity: 'critical',
            source: 'External Network',
            ip: '203.0.113.45',
            description: 'APT detected targeting financial systems',
            time: '14:49:22'
        },
        {
            id: 2,
            title: 'SQL Injection Attempts',
            severity: 'high',
            source: 'Web Application',
            ip: '198.51.100.23',
            description: 'Multiple SQL injection attempts detected',
            time: '14:47:15'
        },
        {
            id: 3,
            title: 'Phishing Campaign',
            severity: 'medium',
            source: 'Email Gateway',
            ip: '192.0.2.67',
            description: 'Phishing campaign with malicious attachments',
            time: '14:45:03'
        },
        {
            id: 4,
            title: 'Port Scanning',
            severity: 'low',
            source: 'Internal Network',
            ip: '192.168.1.105',
            description: 'Unauthorized port scanning detected',
            time: '14:42:18'
        }
    ];
    
    displayThreats(threats);
}

function displayThreats(threats) {
    const container = document.getElementById('threats-list');
    if (!container) return;
    
    container.innerHTML = '';
    
    threats.forEach(threat => {
        const card = document.createElement('div');
        card.className = `threat-card ${threat.severity}`;
        card.innerHTML = `
            <div class="threat-header">
                <h4>${threat.title}</h4>
                <span class="threat-level">${threat.severity.toUpperCase()}</span>
            </div>
            <div class="threat-source">
                <i class="fas fa-network-wired"></i> ${threat.source}
                <span class="threat-ip">${threat.ip}</span>
            </div>
            <p>${threat.description}</p>
            <div class="threat-time">
                <i class="fas fa-clock"></i> ${threat.time}
            </div>
            <div class="threat-actions">
                <button class="threat-btn block" onclick="blockThreat(${threat.id})">
                    <i class="fas fa-ban"></i> Block
                </button>
                <button class="threat-btn analyze" onclick="analyzeThreat(${threat.id})">
                    <i class="fas fa-search"></i> Analyze
                </button>
            </div>
        `;
        container.appendChild(card);
    });
}

function blockThreat(id) {
    showToast('Threat blocked successfully', 'success');
    addActivity('success', 'Threat Blocked', 'Malicious activity has been blocked');
}

function analyzeThreat(id) {
    showToast('Analyzing threat...', 'info');
    setTimeout(() => {
        showToast('Threat analysis complete', 'success');
    }, 1500);
}

// Quick actions
function runScan() {
    showToast('Running quick security scan...', 'info');
    setTimeout(() => {
        showToast('Quick scan complete: No threats found', 'success');
        addActivity('success', 'Quick Scan', 'No security issues detected');
    }, 2000);
}

function updateFirewall() {
    showToast('Updating firewall rules...', 'info');
    setTimeout(() => {
        showToast('Firewall updated successfully', 'success');
        addActivity('info', 'Firewall Updated', 'Latest security rules applied');
    }, 1500);
}

function generateReport() {
    showToast('Generating security report...', 'info');
    setTimeout(() => {
        // Create and download report
        const report = {
            timestamp: new Date().toISOString(),
            summary: {
                threats: securityData.threats.length,
                vulnerabilities: securityData.vulnerabilities.length,
                systemHealth: '92%',
                recommendations: [
                    'Update all software patches',
                    'Review firewall rules',
                    'Implement multi-factor authentication'
                ]
            }
        };
        
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'security-report.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        showToast('Report downloaded successfully', 'success');
    }, 1000);
}

function backupSystem() {
    showToast('Creating system backup...', 'info');
    setTimeout(() => {
        showToast('Backup created successfully', 'success');
        addActivity('info', 'System Backup', 'Full system backup completed');
    }, 2000);
}

// Visualization functions
function drawThreatMap() {
    const canvas = document.getElementById('threat-canvas');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    canvas.width = canvas.parentElement.clientWidth;
    canvas.height = canvas.parentElement.clientHeight;
    
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Draw threat locations
    const locations = [
        { x: canvas.width * 0.2, y: canvas.height * 0.3, country: 'US', threats: 15 },
        { x: canvas.width * 0.8, y: canvas.height * 0.3, country: 'CN', threats: 12 },
        { x: canvas.width * 0.5, y: canvas.height * 0.2, country: 'RU', threats: 8 },
        { x: canvas.width * 0.4, y: canvas.height * 0.5, country: 'EU', threats: 6 },
        { x: canvas.width * 0.7, y: canvas.height * 0.7, country: 'JP', threats: 4 },
        { x: canvas.width * 0.3, y: canvas.height * 0.7, country: 'BR', threats: 3 }
    ];
    
    locations.forEach(loc => {
        // Draw threat circle
        ctx.beginPath();
        ctx.arc(loc.x, loc.y, loc.threats, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255, 46, 99, ${0.2 + loc.threats * 0.02})`;
        ctx.fill();
        
        // Draw center dot
        ctx.beginPath();
        ctx.arc(loc.x, loc.y, 6, 0, Math.PI * 2);
        ctx.fillStyle = loc.threats > 10 ? '#ff2e63' : 
                       loc.threats > 5 ? '#ff6b6b' : '#ffd166';
        ctx.fill();
        
        // Draw label
        ctx.fillStyle = '#e6f1ff';
        ctx.font = '12px Arial';
        ctx.textAlign = 'center';
        ctx.fillText(loc.country, loc.x, loc.y - 20);
    });
}

function drawNetworkGraph() {
    const canvas = document.getElementById('network-canvas');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    canvas.width = canvas.parentElement.clientWidth;
    canvas.height = canvas.parentElement.clientHeight;
    
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Draw network nodes
    const nodes = [
        { x: canvas.width * 0.2, y: canvas.height * 0.5, label: 'Server' },
        { x: canvas.width * 0.8, y: canvas.height * 0.5, label: 'Cloud' },
        { x: canvas.width * 0.5, y: canvas.height * 0.2, label: 'Router' },
        { x: canvas.width * 0.5, y: canvas.height * 0.8, label: 'Firewall' }
    ];
    
    // Draw connections
    ctx.strokeStyle = 'rgba(100, 255, 218, 0.3)';
    ctx.lineWidth = 1;
    
    nodes.forEach((node1, i) => {
        nodes.forEach((node2, j) => {
            if (i < j && Math.random() > 0.5) {
                ctx.beginPath();
                ctx.moveTo(node1.x, node1.y);
                ctx.lineTo(node2.x, node2.y);
                ctx.stroke();
            }
        });
    });
    
    // Draw nodes
    nodes.forEach(node => {
        ctx.beginPath();
        ctx.arc(node.x, node.y, 15, 0, Math.PI * 2);
        ctx.fillStyle = '#64ffda';
        ctx.fill();
        ctx.strokeStyle = '#0a192f';
        ctx.lineWidth = 2;
        ctx.stroke();
        
        // Draw label
        ctx.fillStyle = '#e6f1ff';
        ctx.font = '12px Arial';
        ctx.textAlign = 'center';
        ctx.fillText(node.label, node.x, node.y + 30);
    });
}

// Initialize visualizations
setInterval(drawThreatMap, 5000);
setInterval(drawNetworkGraph, 3000);

// Export functions for use in app.js
window.content = {
    showLoading,
    showToast,
    updateTime,
    addActivity,
    calculatePasswordStrength,
    updatePasswordStrengthVisual,
    generatePassword,
    copyPassword,
    togglePassword,
    startScan,
    loadThreats,
    blockThreat,
    analyzeThreat,
    runScan,
    updateFirewall,
    generateReport,
    backupSystem,
    drawThreatMap,
    drawNetworkGraph
};
