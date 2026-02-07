// app.js - Main application controller

class CyberSecurityApp {
    constructor() {
        this.currentSection = 'dashboard';
        this.initializeApp();
    }
    
    initializeApp() {
        this.setupNavigation();
        this.setupEventListeners();
        this.setupRealTimeUpdates();
        this.initializeSections();
        
        // Add CSS animations
        this.addCustomStyles();
        
        // Simulate initial data loading
        this.simulateInitialData();
        
        console.log('CyberSecurity App initialized successfully');
    }
    
    setupNavigation() {
        // Handle navigation clicks
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const section = item.getAttribute('data-section');
                this.switchSection(section);
                
                // Update active state
                document.querySelectorAll('.nav-item').forEach(nav => {
                    nav.classList.remove('active');
                });
                item.classList.add('active');
            });
        });
        
        // Handle hash changes
        window.addEventListener('hashchange', () => {
            const hash = window.location.hash.substring(1) || 'dashboard';
            this.switchSection(hash);
        });
        
        // Initial section from hash
        const initialHash = window.location.hash.substring(1) || 'dashboard';
        this.switchSection(initialHash);
    }
    
    switchSection(section) {
        // Hide all sections
        document.querySelectorAll('.content-section').forEach(sec => {
            sec.classList.remove('active');
        });
        
        // Show selected section
        const targetSection = document.getElementById(section);
        if (targetSection) {
            targetSection.classList.add('active');
            this.currentSection = section;
            
            // Update page title
            this.updatePageTitle(section);
            
            // Update URL hash
            window.location.hash = section;
            
            // Trigger section-specific initialization
            this.initializeSection(section);
        }
    }
    
    updatePageTitle(section) {
        const titles = {
            dashboard: { main: 'Security Dashboard', sub: 'Real-time monitoring and threat analysis' },
            scanner: { main: 'Vulnerability Scanner', sub: 'Scan systems for security vulnerabilities' },
            password: { main: 'Password Analyzer', sub: 'Test and improve password security' },
            threats: { main: 'Threat Detection', sub: 'Real-time threat monitoring and analysis' },
            network: { main: 'Network Traffic', sub: 'Visualize and analyze network activity' },
            tools: { main: 'Security Tools', sub: 'Collection of cybersecurity utilities' },
            reports: { main: 'Security Reports', sub: 'Generate and view security reports' }
        };
        
        const title = titles[section] || titles.dashboard;
        SecurityUI.updatePageTitle(title.main, title.sub);
    }
    
    initializeSection(section) {
        switch(section) {
            case 'dashboard':
                SecurityVisualizations.initThreatMap();
                break;
            case 'network':
                SecurityVisualizations.initNetworkTraffic();
                break;
            case 'threats':
                SecurityTools.generateThreatFeed();
                break;
            case 'password':
                // Ensure password analyzer is initialized
                const passwordInput = document.getElementById('passwordInput');
                if (passwordInput && !passwordInput.value) {
                    passwordInput.value = 'TestPassword123!';
                    SecurityTools.analyzePassword(passwordInput.value);
                }
                break;
        }
    }
    
    initializeSections() {
        // Initialize all sections
        this.initializeSection('dashboard');
        this.initializeSection('network');
        SecurityTools.initTools();
    }
    
    setupEventListeners() {
        // Notification bell
        const notificationBell = document.querySelector('.notification-bell');
        if (notificationBell) {
            notificationBell.addEventListener('click', SecurityUI.toggleNotificationCenter);
        }
        
        // Mark all notifications as read
        const markReadBtn = document.createElement('button');
        markReadBtn.className = 'btn-mark-read';
        markReadBtn.innerHTML = '<i class="fas fa-check-double"></i> Mark All Read';
        markReadBtn.addEventListener('click', SecurityUI.markAllNotificationsRead);
        
        const notificationHeader = document.querySelector('.notification-header');
        if (notificationHeader) {
            notificationHeader.appendChild(markReadBtn);
        }
        
        // Scanner controls
        const scanButton = document.querySelector('.btn-scan-large');
        if (scanButton) {
            scanButton.addEventListener('click', () => {
                const target = document.getElementById('targetInput').value;
                const scanType = document.getElementById('scanType').value;
                
                if (!target) {
                    SecurityUI.showToast('Please enter a target to scan', 'warning');
                    return;
                }
                
                SecurityTools.scanVulnerabilities(target, scanType);
            });
        }
        
        // Password visibility toggle
        const eyeButton = document.querySelector('.btn-eye');
        if (eyeButton) {
            eyeButton.addEventListener('click', this.togglePasswordVisibility);
        }
        
        // Copy password button
        const copyButton = document.querySelector('.btn-copy');
        if (copyButton) {
            copyButton.addEventListener('click', () => {
                const password = document.getElementById('generatedPassword').value;
                if (password) {
                    SecurityUtils.copyToClipboard(password);
                }
            });
        }
        
        // Encrypt/Decrypt buttons
        document.querySelectorAll('button[onclick*="encryptText"], button[onclick*="decryptText"]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                if (btn.onclick.toString().includes('encryptText')) {
                    SecurityTools.encryptText();
                } else {
                    SecurityTools.decryptText();
                }
            });
        });
        
        // Quick action buttons
        document.querySelectorAll('.action-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                const action = btn.querySelector('span').textContent.toLowerCase();
                
                switch(action) {
                    case 'run quick scan':
                        SecurityTools.runQuickScan();
                        break;
                    case 'update firewall':
                        SecurityTools.updateFirewall();
                        break;
                    case 'backup system':
                        SecurityTools.backupSystem();
                        break;
                    case 'generate report':
                        SecurityTools.generateReport();
                        break;
                }
            });
        });
        
        // Filter buttons
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                
                const filter = btn.textContent.toLowerCase();
                this.filterActivityLog(filter);
            });
        });
        
        // Threat region selector
        const threatRegion = document.getElementById('threatRegion');
        if (threatRegion) {
            threatRegion.addEventListener('change', () => {
                SecurityVisualizations.initThreatMap();
            });
        }
        
        // Handle keyboard shortcuts
        this.setupKeyboardShortcuts();
        
        // Handle window resize
        window.addEventListener('resize', () => {
            SecurityVisualizations.initThreatMap();
            SecurityVisualizations.initNetworkTraffic();
        });
    }
    
    togglePasswordVisibility() {
        const passwordInput = document.getElementById('passwordInput');
        const eyeIcon = document.querySelector('.btn-eye i');
        
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            eyeIcon.className = 'fas fa-eye-slash';
        } else {
            passwordInput.type = 'password';
            eyeIcon.className = 'fas fa-eye';
        }
    }
    
    filterActivityLog(filter) {
        const activityItems = document.querySelectorAll('.activity-item');
        
        activityItems.forEach(item => {
            if (filter === 'all' || item.classList.contains(filter)) {
                item.style.display = 'flex';
            } else {
                item.style.display = 'none';
            }
        });
    }
    
    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl + S for quick scan
            if (e.ctrlKey && e.key === 's') {
                e.preventDefault();
                SecurityTools.runQuickScan();
            }
            
            // Ctrl + F for focus search
            if (e.ctrlKey && e.key === 'f') {
                e.preventDefault();
                document.getElementById('targetInput')?.focus();
            }
            
            // Ctrl + N for notifications
            if (e.ctrlKey && e.key === 'n') {
                e.preventDefault();
                SecurityUI.toggleNotificationCenter();
            }
            
            // Escape to close modals/notifications
            if (e.key === 'Escape') {
                document.querySelector('.modal.active')?.remove();
                document.getElementById('notificationCenter')?.classList.remove('active');
            }
            
            // Number keys for navigation
            if (!e.ctrlKey && !e.altKey && e.key >= '1' && e.key <= '7') {
                const sections = ['dashboard', 'scanner', 'password', 'threats', 'network', 'tools', 'reports'];
                const index = parseInt(e.key) - 1;
                if (sections[index]) {
                    this.switchSection(sections[index]);
                    
                    // Update active nav
                    document.querySelectorAll('.nav-item').forEach((nav, i) => {
                        if (i === index) {
                            nav.classList.add('active');
                        } else {
                            nav.classList.remove('active');
                        }
                    });
                }
            }
        });
    }
    
    setupRealTimeUpdates() {
        // Update metrics every 30 seconds
        setInterval(() => {
            SecurityUI.updateMetrics();
            
            // Simulate new threats occasionally
            if (Math.random() > 0.8 && this.currentSection === 'threats') {
                SecurityTools.generateThreatFeed();
            }
        }, 30000);
        
        // Update threat map every 10 seconds
        setInterval(() => {
            if (this.currentSection === 'dashboard') {
                SecurityVisualizations.initThreatMap();
            }
        }, 10000);
        
        // Simulate real-time network activity
        setInterval(() => {
            if (this.currentSection === 'network') {
                SecurityVisualizations.initNetworkTraffic();
            }
        }, 5000);
    }
    
    addCustomStyles() {
        // Add custom CSS for animations
        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideIn {
                from {
                    transform: translateX(100%);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
            
            @keyframes slideOut {
                from {
                    transform: translateX(0);
                    opacity: 1;
                }
                to {
                    transform: translateX(100%);
                    opacity: 0;
                }
            }
            
            @keyframes pulse {
                0% {
                    transform: scale(1);
                    opacity: 1;
                }
                50% {
                    transform: scale(1.05);
                    opacity: 0.7;
                }
                100% {
                    transform: scale(1);
                    opacity: 1;
                }
            }
            
            .status-open {
                color: #00ff88;
                background: rgba(0, 255, 136, 0.1);
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 0.8rem;
            }
            
            .risk-level {
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 0.8rem;
                font-weight: 600;
            }
            
            .risk-level.high {
                background: rgba(255, 46, 99, 0.1);
                color: #ff2e63;
            }
            
            .risk-level.medium {
                background: rgba(255, 209, 102, 0.1);
                color: #ffd166;
            }
            
            .risk-level.low {
                background: rgba(78, 205, 196, 0.1);
                color: #4ecdc4;
            }
            
            .btn-mark-read {
                background: rgba(100, 255, 218, 0.1);
                border: 1px solid rgba(100, 255, 218, 0.3);
                color: var(--accent-blue);
                padding: 6px 12px;
                border-radius: 6px;
                font-size: 0.9rem;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            
            .btn-mark-read:hover {
                background: rgba(100, 255, 218, 0.2);
            }
            
            .btn-primary {
                background: var(--gradient-accent);
                color: var(--primary-dark);
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: 600;
                cursor: pointer;
            }
            
            .btn-secondary {
                background: rgba(255, 255, 255, 0.1);
                color: var(--text-primary);
                border: 1px solid rgba(255, 255, 255, 0.2);
                padding: 10px 20px;
                border-radius: 6px;
                cursor: pointer;
            }
            
            .ports-table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
            }
            
            .ports-table th {
                background: rgba(10, 25, 47, 0.5);
                padding: 12px;
                text-align: left;
                font-weight: 600;
                color: var(--accent-blue);
            }
            
            .ports-table td {
                padding: 12px;
                border-bottom: 1px solid rgba(100, 255, 218, 0.1);
            }
            
            .ports-table tr:hover {
                background: rgba(100, 255, 218, 0.05);
            }
            
            .scan-summary {
                margin-bottom: 30px;
            }
            
            .summary-stats {
                display: flex;
                gap: 30px;
                justify-content: center;
            }
            
            .summary-stats .stat {
                text-align: center;
                padding: 20px;
                background: rgba(10, 25, 47, 0.3);
                border-radius: 8px;
                min-width: 100px;
            }
            
            .stat-value {
                font-size: 2rem;
                font-weight: 700;
                color: var(--accent-blue);
                font-family: 'JetBrains Mono', monospace;
            }
            
            .stat-label {
                font-size: 0.9rem;
                color: var(--text-muted);
                margin-top: 5px;
            }
            
            .analysis-section {
                margin-bottom: 25px;
                padding-bottom: 25px;
                border-bottom: 1px solid rgba(100, 255, 218, 0.1);
            }
            
            .analysis-section h4 {
                display: flex;
                align-items: center;
                gap: 10px;
                margin-bottom: 10px;
                color: var(--accent-blue);
            }
            
            .analysis-section ul {
                padding-left: 20px;
                margin-top: 10px;
            }
            
            .analysis-section li {
                margin-bottom: 8px;
                color: var(--text-secondary);
            }
            
            .risk-score {
                text-align: center;
                padding: 20px;
                background: rgba(255, 46, 99, 0.1);
                border-radius: 8px;
                border: 1px solid rgba(255, 46, 99, 0.3);
            }
            
            .score-value {
                font-size: 1.5rem;
                font-weight: 700;
                margin-bottom: 5px;
            }
            
            .score-value.high {
                color: #ff2e63;
            }
            
            .score-description {
                color: var(--text-secondary);
                font-size: 0.9rem;
            }
        `;
        document.head.appendChild(style);
    }
    
    simulateInitialData() {
        // Simulate initial notifications
        setTimeout(() => {
            SecurityUI.addNotification('info', 'System Online', 'All security systems are now operational');
            SecurityUI.addNotification('warning', 'Suspicious Activity', 'Multiple login attempts detected from unusual location');
            SecurityUI.addNotification('critical', 'Critical Alert', 'Potential malware signature detected in network traffic');
            
            // Simulate initial threats
            SecurityTools.generateThreatFeed();
        }, 2000);
        
        // Simulate initial vulnerabilities
        setTimeout(() => {
            const vulnerabilities = SecurityTools.generateVulnerabilities('192.168.1.1', 'quick');
            SecurityTools.displayVulnerabilityResults(vulnerabilities);
        }, 3000);
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    window.cyberSecurityApp = new CyberSecurityApp();
});

// Global error handling
window.addEventListener('error', (event) => {
    console.error('Application error:', event.error);
    SecurityUI.showToast('An error occurred. Check console for details.', 'error');
});

// Service Worker registration for PWA (optional)
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js').then(registration => {
            console.log('ServiceWorker registration successful');
        }).catch(err => {
            console.log('ServiceWorker registration failed: ', err);
        });
    });
}

// Export for module usage (if needed)
export { CyberSecurityApp };
