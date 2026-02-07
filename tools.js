// tools.js - Security tools implementation

class SecurityTools {
    // Vulnerability Scanner
    static async scanVulnerabilities(target, scanType = 'quick') {
        SecurityUI.showLoading(`Scanning ${target} for vulnerabilities...`);
        
        // Simulate scan process
        await SecurityUtils.simulateDelay(2000);
        
        // Generate simulated vulnerabilities
        const vulnerabilities = this.generateVulnerabilities(target, scanType);
        
        // Update UI with results
        this.displayVulnerabilityResults(vulnerabilities);
        
        // Add to activity log
        SecurityUI.addActivityLog('scan', 'Vulnerability Scan Complete', 
            `Found ${vulnerabilities.length} vulnerabilities on ${target}`);
        
        SecurityUI.hideLoading();
        SecurityUI.showToast(`Scan complete: ${vulnerabilities.length} vulnerabilities found`, 
            vulnerabilities.length > 0 ? 'warning' : 'success');
        
        return vulnerabilities;
    }
    
    static generateVulnerabilities(target, scanType) {
        const vulnerabilities = [];
        const numVulns = scanType === 'full' ? 8 : scanType === 'port' ? 5 : 3;
        
        const vulnTypes = [
            {
                title: 'Outdated Software Version',
                severity: 'high',
                description: 'Running outdated version with known security vulnerabilities',
                remediation: 'Update to the latest version immediately',
                cve: 'CVE-2024-12345'
            },
            {
                title: 'Weak SSL/TLS Configuration',
                severity: 'medium',
                description: 'Using weak cipher suites and outdated TLS versions',
                remediation: 'Update TLS configuration and disable weak ciphers',
                cve: 'CVE-2024-12346'
            },
            {
                title: 'Open Port Vulnerabilities',
                severity: 'critical',
                description: 'Multiple unnecessary ports open to public access',
                remediation: 'Close unused ports and restrict access',
                port: 22
            },
            {
                title: 'SQL Injection Vulnerability',
                severity: 'critical',
                description: 'Input fields vulnerable to SQL injection attacks',
                remediation: 'Implement parameterized queries and input validation',
                cve: 'CVE-2024-12347'
            },
            {
                title: 'Cross-Site Scripting (XSS)',
                severity: 'high',
                description: 'User input not properly sanitized in web application',
                remediation: 'Implement proper input sanitization and output encoding',
                cve: 'CVE-2024-12348'
            },
            {
                title: 'Directory Traversal',
                severity: 'medium',
                description: 'Unauthorized access to directory structures',
                remediation: 'Implement proper access controls and path validation',
                cve: 'CVE-2024-12349'
            },
            {
                title: 'Information Disclosure',
                severity: 'low',
                description: 'Sensitive information exposed in error messages',
                remediation: 'Configure proper error handling and logging',
                cve: 'CVE-2024-12350'
            },
            {
                title: 'Brute Force Vulnerable',
                severity: 'medium',
                description: 'No rate limiting on authentication attempts',
                remediation: 'Implement rate limiting and account lockout policies',
                cve: 'CVE-2024-12351'
            }
        ];
        
        for (let i = 0; i < numVulns; i++) {
            const randomVuln = vulnTypes[Math.floor(Math.random() * vulnTypes.length)];
            vulnerabilities.push({
                id: SecurityUtils.generateId('vuln_'),
                title: randomVuln.title,
                severity: randomVuln.severity,
                description: randomVuln.description,
                remediation: randomVuln.remediation,
                cve: randomVuln.cve,
                port: randomVuln.port,
                target: target,
                timestamp: new Date().toISOString()
            });
        }
        
        return vulnerabilities;
    }
    
    static displayVulnerabilityResults(vulnerabilities) {
        const container = document.getElementById('vulnerabilityList');
        if (!container) return;
        
        container.innerHTML = '';
        
        // Count by severity
        const counts = { critical: 0, high: 0, medium: 0, low: 0 };
        
        vulnerabilities.forEach(vuln => {
            counts[vuln.severity] = (counts[vuln.severity] || 0) + 1;
            
            const vulnElement = document.createElement('div');
            vulnElement.className = `vulnerability-item ${vuln.severity}`;
            vulnElement.innerHTML = `
                <div class="vuln-header">
                    <div class="vuln-title">${vuln.title}</div>
                    <div class="vuln-severity ${vuln.severity}">${vuln.severity.toUpperCase()}</div>
                </div>
                <div class="vuln-description">${vuln.description}</div>
                <div class="vuln-details">
                    ${vuln.cve ? `<span><i class="fas fa-bug"></i> ${vuln.cve}</span>` : ''}
                    ${vuln.port ? `<span><i class="fas fa-plug"></i> Port ${vuln.port}</span>` : ''}
                    <span><i class="fas fa-clock"></i> ${new Date(vuln.timestamp).toLocaleTimeString()}</span>
                </div>
                <div class="vuln-remediation">
                    <div class="remediation-title">
                        <i class="fas fa-wrench"></i> Recommended Fix
                    </div>
                    ${vuln.remediation}
                </div>
            `;
            
            container.appendChild(vulnElement);
        });
        
        // Update counts
        document.getElementById('criticalCount')?.textContent = counts.critical;
        document.getElementById('highCount')?.textContent = counts.high;
        document.getElementById('mediumCount')?.textContent = counts.medium;
        document.getElementById('lowCount')?.textContent = counts.low;
        
        // Create chart if needed
        SecurityVisualizations.createVulnerabilityChart(vulnerabilities);
    }
    
    // Password Tools
    static analyzePassword(password) {
        SecurityVisualizations.updatePasswordStrength(password);
    }
    
    static generatePassword() {
        const length = parseInt(document.getElementById('lengthSlider')?.value) || 16;
        const options = {
            uppercase: document.getElementById('uppercase')?.checked || false,
            lowercase: document.getElementById('lowercase')?.checked || false,
            numbers: document.getElementById('numbers')?.checked || false,
            symbols: document.getElementById('symbols')?.checked || false
        };
        
        // Ensure at least one option is selected
        if (!Object.values(options).some(v => v)) {
            options.lowercase = true;
            document.getElementById('lowercase').checked = true;
        }
        
        const password = SecurityUtils.generatePassword(length, options);
        document.getElementById('generatedPassword').value = password;
        
        // Analyze the generated password
        this.analyzePassword(password);
        
        SecurityUI.showToast('Password generated successfully!', 'success');
    }
    
    static async checkPasswordBreach(password) {
        if (!password) {
            SecurityUI.showToast('Please enter a password to check', 'warning');
            return;
        }
        
        SecurityUI.showLoading('Checking password breaches...');
        
        // Simulate API call to HaveIBeenPwned
        await SecurityUtils.simulateDelay(1500);
        
        // Simulated breach data
        const breaches = Math.random() > 0.7 ? [
            {
                name: 'Collection #1',
                date: '2019-01-07',
                count: '773,000,000',
                description: 'Compilation of many data breaches'
            },
            {
                name: 'Anti Public',
                date: '2017-12-01',
                count: '458,000,000',
                description: 'Combination of previous breaches'
            }
        ] : [];
        
        this.displayBreachResults(breaches);
        SecurityUI.hideLoading();
        
        if (breaches.length > 0) {
            SecurityUI.showToast(`Password found in ${breaches.length} data breaches`, 'error');
        } else {
            SecurityUI.showToast('Password not found in known breaches', 'success');
        }
    }
    
    static displayBreachResults(breaches) {
        const container = document.getElementById('breachResults');
        if (!container) return;
        
        if (breaches.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-shield-check"></i>
                    <h3>No Breaches Found</h3>
                    <p>This password was not found in any known data breaches.</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = `
            <div class="alert alert-warning">
                <i class="fas fa-exclamation-triangle"></i>
                <strong>Password Found in ${breaches.length} Data Breaches</strong>
                <p>This password has been exposed in the following breaches:</p>
            </div>
        `;
        
        breaches.forEach(breach => {
            const breachElement = document.createElement('div');
            breachElement.className = 'breach-item';
            breachElement.innerHTML = `
                <div class="breach-name">${breach.name}</div>
                <div class="breach-description">${breach.description}</div>
                <div class="breach-details">
                    <span><i class="fas fa-calendar"></i> ${breach.date}</span>
                    <span><i class="fas fa-database"></i> ${breach.count} records</span>
                </div>
            `;
            container.appendChild(breachElement);
        });
    }
    
    // Threat Detection
    static generateThreatFeed() {
        const threats = [
            {
                id: SecurityUtils.generateId('threat_'),
                level: 'critical',
                source: 'External Network',
                description: 'Advanced Persistent Threat detected targeting financial systems',
                timestamp: new Date().toISOString(),
                sourceIP: SecurityUtils.generateRandomIP()
            },
            {
                id: SecurityUtils.generateId('threat_'),
                level: 'high',
                source: 'Web Application',
                description: 'Multiple SQL injection attempts detected on login page',
                timestamp: new Date(Date.now() - 300000).toISOString(),
                sourceIP: SecurityUtils.generateRandomIP()
            },
            {
                id: SecurityUtils.generateId('threat_'),
                level: 'medium',
                source: 'Email Gateway',
                description: 'Phishing campaign detected with malicious attachments',
                timestamp: new Date(Date.now() - 600000).toISOString(),
                sourceIP: SecurityUtils.generateRandomIP()
            },
            {
                id: SecurityUtils.generateId('threat_'),
                level: 'low',
                source: 'Internal Network',
                description: 'Unauthorized port scanning detected from internal host',
                timestamp: new Date(Date.now() - 900000).toISOString(),
                sourceIP: '192.168.1.105'
            }
        ];
        
        this.displayThreatFeed(threats);
        return threats;
    }
    
    static displayThreatFeed(threats) {
        const container = document.querySelector('.threats-grid');
        if (!container) return;
        
        container.innerHTML = '';
        
        threats.forEach(threat => {
            const threatElement = document.createElement('div');
            threatElement.className = 'threat-card';
            threatElement.innerHTML = `
                <div class="threat-level ${threat.level}">
                    <div class="level-dot"></div>
                    <span class="level-text">${threat.level.toUpperCase()}</span>
                </div>
                <div class="threat-source">
                    <i class="fas fa-network-wired"></i>
                    <span>${threat.source}</span>
                    <span class="threat-ip">${threat.sourceIP}</span>
                </div>
                <div class="threat-description">
                    ${threat.description}
                </div>
                <div class="threat-time">
                    <i class="fas fa-clock"></i>
                    ${new Date(threat.timestamp).toLocaleTimeString()}
                </div>
                <div class="threat-actions">
                    <button class="threat-btn block" onclick="SecurityTools.blockThreat('${threat.id}')">
                        <i class="fas fa-ban"></i> Block
                    </button>
                    <button class="threat-btn analyze" onclick="SecurityTools.analyzeThreat('${threat.id}')">
                        <i class="fas fa-search"></i> Analyze
                    </button>
                </div>
            `;
            
            container.appendChild(threatElement);
        });
    }
    
    static blockThreat(threatId) {
        SecurityUI.showToast('Threat blocked successfully', 'success');
        SecurityUI.addActivityLog('success', 'Threat Blocked', 'Malicious activity has been blocked');
        
        // Remove threat from UI
        document.querySelectorAll('.threat-card').forEach(card => {
            if (card.querySelector('.threat-btn')?.onclick?.toString().includes(threatId)) {
                card.remove();
            }
        });
    }
    
    static analyzeThreat(threatId) {
        SecurityUI.showLoading('Analyzing threat...');
        
        setTimeout(() => {
            SecurityUI.hideLoading();
            SecurityUI.showToast('Threat analysis complete', 'info');
            
            // Show analysis modal
            this.showThreatAnalysisModal(threatId);
        }, 1500);
    }
    
    static showThreatAnalysisModal(threatId) {
        // Create modal
        const modal = document.createElement('div');
        modal.className = 'modal active';
        modal.innerHTML = `
            <div class="modal-content">
                <button class="modal-close" onclick="this.closest('.modal').remove()">
                    <i class="fas fa-times"></i>
                </button>
                <div class="modal-header">
                    <h2><i class="fas fa-search"></i> Threat Analysis</h2>
                </div>
                <div class="modal-body">
                    <div class="analysis-details">
                        <h3>Threat ID: ${threatId}</h3>
                        <div class="analysis-section">
                            <h4><i class="fas fa-info-circle"></i> Threat Details</h4>
                            <p>Detailed analysis of the detected threat pattern and behavior.</p>
                        </div>
                        <div class="analysis-section">
                            <h4><i class="fas fa-shield-alt"></i> Mitigation Steps</h4>
                            <ul>
                                <li>Update firewall rules to block source IP</li>
                                <li>Implement rate limiting on affected services</li>
                                <li>Review system logs for related activity</li>
                                <li>Update security patches</li>
                            </ul>
                        </div>
                        <div class="analysis-section">
                            <h4><i class="fas fa-chart-line"></i> Risk Assessment</h4>
                            <div class="risk-score">
                                <div class="score-value high">HIGH RISK</div>
                                <div class="score-description">Immediate action required</div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn-secondary" onclick="this.closest('.modal').remove()">
                        Close
                    </button>
                    <button class="btn-primary" onclick="SecurityTools.exportThreatReport('${threatId}')">
                        <i class="fas fa-download"></i> Export Report
                    </button>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
    }
    
    static exportThreatReport(threatId) {
        const report = {
            threatId,
            timestamp: new Date().toISOString(),
            analysis: 'Detailed threat analysis report',
            recommendations: [
                'Block source IP in firewall',
                'Update security patches',
                'Monitor network traffic',
                'Review access logs'
            ]
        };
        
        SecurityUtils.exportData(report, `threat-report-${threatId}.json`);
        SecurityUI.showToast('Report exported successfully', 'success');
    }
    
    // Network Tools
    static async portScan(target) {
        if (!SecurityUtils.isValidIP(target) && !SecurityUtils.isValidDomain(target)) {
            SecurityUI.showToast('Invalid target address', 'error');
            return;
        }
        
        SecurityUI.showLoading(`Scanning ports on ${target}...`);
        
        // Simulate port scanning
        await SecurityUtils.simulateDelay(3000);
        
        // Simulated open ports
        const openPorts = [
            { port: 22, service: 'SSH', status: 'open', version: 'OpenSSH 8.2' },
            { port: 80, service: 'HTTP', status: 'open', version: 'nginx/1.18' },
            { port: 443, service: 'HTTPS', status: 'open', version: 'nginx/1.18' },
            { port: 3306, service: 'MySQL', status: 'open', version: 'MySQL 8.0' },
            { port: 8080, service: 'HTTP-ALT', status: 'open', version: 'Apache/2.4' }
        ].filter(() => Math.random() > 0.3); // Randomly filter some ports
        
        this.displayPortScanResults(target, openPorts);
        SecurityUI.hideLoading();
        
        SecurityUI.addActivityLog('scan', 'Port Scan Complete', 
            `Found ${openPorts.length} open ports on ${target}`);
        
        SecurityUI.showToast(`Port scan complete: ${openPorts.length} open ports found`, 
            openPorts.length > 0 ? 'info' : 'success');
    }
    
    static displayPortScanResults(target, ports) {
        // Create results modal
        const modal = document.createElement('div');
        modal.className = 'modal active';
        modal.innerHTML = `
            <div class="modal-content">
                <button class="modal-close" onclick="this.closest('.modal').remove()">
                    <i class="fas fa-times"></i>
                </button>
                <div class="modal-header">
                    <h2><i class="fas fa-search"></i> Port Scan Results</h2>
                    <p>Target: ${target}</p>
                </div>
                <div class="modal-body">
                    <div class="scan-summary">
                        <div class="summary-stats">
                            <div class="stat">
                                <div class="stat-value">${ports.length}</div>
                                <div class="stat-label">Open Ports</div>
                            </div>
                            <div class="stat">
                                <div class="stat-value">${100 - ports.length}</div>
                                <div class="stat-label">Closed Ports</div>
                            </div>
                            <div class="stat">
                                <div class="stat-value">${Math.floor(Math.random() * 5) + 1}</div>
                                <div class="stat-label">Filtered</div>
                            </div>
                        </div>
                    </div>
                    <div class="ports-list">
                        <h3>Open Ports:</h3>
                        ${ports.length > 0 ? `
                            <table class="ports-table">
                                <thead>
                                    <tr>
                                        <th>Port</th>
                                        <th>Service</th>
                                        <th>Status</th>
                                        <th>Version</th>
                                        <th>Risk</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${ports.map(port => `
                                        <tr>
                                            <td>${port.port}</td>
                                            <td>${port.service}</td>
                                            <td><span class="status-open">${port.status}</span></td>
                                            <td>${port.version}</td>
                                            <td>
                                                <span class="risk-level ${
                                                    [22, 3306].includes(port.port) ? 'high' : 
                                                    [80, 443].includes(port.port) ? 'medium' : 'low'
                                                }">
                                                    ${[22, 3306].includes(port.port) ? 'High' : 
                                                      [80, 443].includes(port.port) ? 'Medium' : 'Low'}
                                                </span>
                                            </td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        ` : '<p class="empty-state">No open ports found</p>'}
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn-secondary" onclick="this.closest('.modal').remove()">
                        Close
                    </button>
                    <button class="btn-primary" onclick="SecurityTools.exportScanReport('${target}', ${JSON.stringify(ports)})">
                        <i class="fas fa-download"></i> Export Results
                    </button>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
    }
    
    static exportScanReport(target, ports) {
        const report = {
            target,
            timestamp: new Date().toISOString(),
            ports,
            summary: {
                totalScanned: 1000,
                openPorts: ports.length,
                closedPorts: 1000 - ports.length,
                filteredPorts: Math.floor(Math.random() * 5) + 1
            }
        };
        
        SecurityUtils.exportData(report, `port-scan-${target.replace(/[^a-z0-9]/gi, '-')}.json`);
        SecurityUI.showToast('Scan results exported', 'success');
    }
    
    // Encryption Tools
    static encryptText() {
        const input = document.getElementById('encryptInput');
        const output = document.getElementById('encryptOutput');
        
        if (!input || !output) return;
        
        const encrypted = SecurityUtils.encrypt(input.value);
        output.value = encrypted;
        output.style.color = '#64ffda';
        
        SecurityUI.showToast('Text encrypted successfully', 'success');
    }
    
    static decryptText() {
        const input = document.getElementById('encryptInput');
        const output = document.getElementById('encryptOutput');
        
        if (!input || !output) return;
        
        const decrypted = SecurityUtils.decrypt(input.value);
        output.value = decrypted;
        output.style.color = '#00ff88';
        
        SecurityUI.showToast('Text decrypted successfully', 'success');
    }
    
    // Quick Actions
    static async runQuickScan() {
        SecurityUI.showLoading('Running quick security scan...');
        
        // Simulate scan process
        await SecurityUtils.simulateDelay(2500);
        
        // Random results
        const threats = Math.random() > 0.7 ? 1 : 0;
        const vulnerabilities = Math.floor(Math.random() * 3);
        
        SecurityUI.hideLoading();
        
        if (threats > 0 || vulnerabilities > 0) {
            SecurityUI.showToast(`Scan found ${threats} threats and ${vulnerabilities} vulnerabilities`, 'warning');
            SecurityUI.addActivityLog('warning', 'Quick Scan Complete', 
                `Found ${threats} active threats and ${vulnerabilities} vulnerabilities`);
        } else {
            SecurityUI.showToast('Quick scan completed: No issues found', 'success');
            SecurityUI.addActivityLog('success', 'Quick Scan Complete', 'No security issues detected');
        }
        
        // Update metrics
        SecurityUI.updateMetrics();
    }
    
    static updateFirewall() {
        SecurityUI.showLoading('Updating firewall rules...');
        
        setTimeout(() => {
            SecurityUI.hideLoading();
            SecurityUI.showToast('Firewall updated successfully', 'success');
            SecurityUI.addActivityLog('success', 'Firewall Updated', 'Latest security rules applied');
        }, 1500);
    }
    
    static backupSystem() {
        SecurityUI.showLoading('Creating system backup...');
        
        setTimeout(() => {
            SecurityUI.hideLoading();
            SecurityUI.showToast('System backup created successfully', 'success');
            SecurityUI.addActivityLog('info', 'System Backup', 'Full system backup completed');
        }, 2000);
    }
    
    static generateReport() {
        SecurityUI.showLoading('Generating security report...');
        
        setTimeout(() => {
            const report = {
                timestamp: new Date().toISOString(),
                summary: {
                    threats: securityData.threats.length,
                    scans: securityData.scans.length,
                    vulnerabilities: securityData.vulnerabilities.length,
                    systemHealth: '92%',
                    recommendations: [
                        'Update all software patches',
                        'Review firewall rules',
                        'Conduct penetration testing',
                        'Implement multi-factor authentication'
                    ]
                }
            };
            
            SecurityUtils.exportData(report, 'security-report.json');
            SecurityUI.hideLoading();
            SecurityUI.showToast('Security report generated', 'success');
        }, 1000);
    }
    
    // Initialize all tools
    static initTools() {
        // Password input listener
        const passwordInput = document.getElementById('passwordInput');
        if (passwordInput) {
            passwordInput.addEventListener('input', (e) => {
                this.analyzePassword(e.target.value);
            });
        }
        
        // Generate initial password
        this.generatePassword();
        
        // Generate threat feed
        this.generateThreatFeed();
        
        // Initialize other tool listeners
        this.initToolListeners();
    }
    
    static initToolListeners() {
        // Quick scan button
        const quickScanBtn = document.getElementById('quickScanBtn');
        if (quickScanBtn) {
            quickScanBtn.addEventListener('click', this.runQuickScan);
        }
        
        // Generate password button
        const generateBtn = document.querySelector('.btn-generate');
        if (generateBtn) {
            generateBtn.addEventListener('click', this.generatePassword);
        }
        
        // Length slider
        const lengthSlider = document.getElementById('lengthSlider');
        if (lengthSlider) {
            lengthSlider.addEventListener('input', (e) => {
                document.getElementById('lengthValue').textContent = e.target.value;
            });
        }
        
        // Check breach button
        const checkBtn = document.querySelector('.btn-check');
        if (checkBtn) {
            checkBtn.addEventListener('click', () => {
                const input = document.getElementById('breachCheckInput');
                this.checkPasswordBreach(input.value);
            });
        }
    }
}

// Initialize tools when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    setTimeout(() => {
        SecurityTools.initTools();
    }, 1500);
});

// Export for global use
window.SecurityTools = SecurityTools;
