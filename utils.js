// utils.js - Utility functions for cybersecurity dashboard

// DOM Elements
const elements = {
    loadingScreen: document.getElementById('loadingScreen'),
    pageTitle: document.getElementById('pageTitle'),
    pageSubtitle: document.getElementById('pageSubtitle'),
    currentTime: document.getElementById('currentTime'),
    activityLog: document.getElementById('activityLog'),
    criticalThreats: document.getElementById('criticalThreats'),
    protectedSystems: document.getElementById('protectedSystems'),
    lastScanTime: document.getElementById('lastScanTime'),
    networkTraffic: document.getElementById('networkTraffic'),
    healthScore: document.getElementById('healthScore'),
    notificationList: document.getElementById('notificationList'),
    notificationCount: document.querySelector('.notification-count')
};

// Configuration
const config = {
    apiEndpoints: {
        threatIntel: 'https://api.threatintelplatform.com/v1',
        virusTotal: 'https://www.virustotal.com/api/v3',
        breachCheck: 'https://haveibeenpwned.com/api/v3'
    },
    settings: {
        autoRefresh: true,
        scanInterval: 300000, // 5 minutes
        notifications: true,
        darkMode: true
    },
    simulatedData: {
        threats: ['Malware', 'Phishing', 'DDoS', 'Ransomware', 'Brute Force', 'SQL Injection'],
        locations: ['US', 'CN', 'RU', 'DE', 'JP', 'IN', 'BR', 'UK'],
        ips: ['192.168.1.', '10.0.0.', '172.16.0.', '203.0.113.']
    }
};

// Security Data Storage
const securityData = {
    threats: [],
    scans: [],
    vulnerabilities: [],
    notifications: [],
    metrics: {
        totalScans: 0,
        threatsBlocked: 0,
        vulnerabilitiesFound: 0,
        systemUptime: '99.9%'
    }
};

// Utility Functions
class SecurityUtils {
    // Time and Date
    static updateTime() {
        const now = new Date();
        const timeString = now.toLocaleTimeString('en-US', { 
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
        if (elements.currentTime) {
            elements.currentTime.textContent = timeString;
        }
        
        // Update page title with time
        document.title = `CyberShield PRO | ${timeString}`;
    }

    // Format bytes to human readable
    static formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }

    // Generate random IP
    static generateRandomIP() {
        const octets = [];
        for (let i = 0; i < 4; i++) {
            octets.push(Math.floor(Math.random() * 255));
        }
        return octets.join('.');
    }

    // Calculate password entropy
    static calculateEntropy(password) {
        if (!password) return 0;
        
        let poolSize = 0;
        if (/[a-z]/.test(password)) poolSize += 26;
        if (/[A-Z]/.test(password)) poolSize += 26;
        if (/[0-9]/.test(password)) poolSize += 10;
        if (/[^A-Za-z0-9]/.test(password)) poolSize += 32;
        
        return Math.log2(Math.pow(poolSize, password.length));
    }

    // Simulate API delay
    static simulateDelay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // Generate unique ID
    static generateId(prefix = '') {
        return prefix + Date.now().toString(36) + Math.random().toString(36).substr(2);
    }

    // Validate IP address
    static isValidIP(ip) {
        const ipRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        return ipRegex.test(ip);
    }

    // Validate domain
    static isValidDomain(domain) {
        const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
        return domainRegex.test(domain);
    }

    // Encrypt text (simple Caesar cipher for demo)
    static encrypt(text, shift = 3) {
        return text.split('').map(char => {
            const code = char.charCodeAt(0);
            if ((code >= 65 && code <= 90) || (code >= 97 && code <= 122)) {
                const base = code >= 97 ? 97 : 65;
                return String.fromCharCode(((code - base + shift) % 26) + base);
            }
            return char;
        }).join('');
    }

    // Decrypt text
    static decrypt(text, shift = 3) {
        return SecurityUtils.encrypt(text, 26 - shift);
    }

    // Generate hash (simulated)
    static async generateHash(text, algorithm = 'sha256') {
        await SecurityUtils.simulateDelay(500);
        
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        
        // Simulate different hash algorithms
        const hashMap = {
            'md5': '098f6bcd4621d373cade4e832627b4f6',
            'sha1': 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3',
            'sha256': '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
            'sha512': 'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff'
        };
        
        return hashMap[algorithm] || hashMap.sha256;
    }

    // Calculate risk score
    static calculateRiskScore(vulnerabilities) {
        let score = 0;
        vulnerabilities.forEach(vuln => {
            switch(vuln.severity) {
                case 'critical': score += 10; break;
                case 'high': score += 7; break;
                case 'medium': score += 4; break;
                case 'low': score += 1; break;
            }
        });
        return Math.min(100, score);
    }

    // Generate random threat data
    static generateThreatData() {
        const threats = [
            { type: 'malware', name: 'Trojan Horse', severity: 'critical' },
            { type: 'phishing', name: 'Spear Phishing', severity: 'high' },
            { type: 'ddos', name: 'DDoS Attack', severity: 'high' },
            { type: 'ransomware', name: 'WannaCry Variant', severity: 'critical' },
            { type: 'brute', name: 'Brute Force Attempt', severity: 'medium' },
            { type: 'sql', name: 'SQL Injection', severity: 'high' }
        ];
        
        return threats[Math.floor(Math.random() * threats.length)];
    }

    // Parse URL parameters
    static getUrlParams() {
        const params = {};
        window.location.search.substring(1).split('&').forEach(param => {
            const [key, value] = param.split('=');
            if (key) params[key] = decodeURIComponent(value || '');
        });
        return params;
    }

    // Debounce function
    static debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    // Throttle function
    static throttle(func, limit) {
        let inThrottle;
        return function(...args) {
            if (!inThrottle) {
                func.apply(this, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }

    // Copy to clipboard
    static copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            SecurityUI.showToast('Copied to clipboard!');
        }).catch(err => {
            console.error('Failed to copy: ', err);
            SecurityUI.showToast('Failed to copy to clipboard', 'error');
        });
    }

    // Export data as JSON
    static exportData(data, filename = 'security-report.json') {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // Import data from file
    static importData(file, callback) {
        const reader = new FileReader();
        reader.onload = function(e) {
            try {
                const data = JSON.parse(e.target.result);
                callback(data);
            } catch (error) {
                SecurityUI.showToast('Invalid file format', 'error');
            }
        };
        reader.readAsText(file);
    }

    // Calculate password strength
    static calculatePasswordStrength(password) {
        if (!password) return { score: 0, strength: 'Very Weak' };
        
        let score = 0;
        const feedback = [];
        
        // Length check
        if (password.length >= 8) score += 20;
        if (password.length >= 12) score += 10;
        if (password.length >= 16) score += 10;
        
        // Character variety
        if (/[a-z]/.test(password)) score += 10;
        if (/[A-Z]/.test(password)) score += 10;
        if (/[0-9]/.test(password)) score += 10;
        if (/[^A-Za-z0-9]/.test(password)) score += 10;
        
        // Pattern checks
        if (!/(.)\1{2,}/.test(password)) score += 10; // No repeating chars
        if (!/(012|123|234|345|456|567|678|789)/.test(password)) score += 10; // No simple sequences
        if (!/(qwert|asdfg|zxcvb)/i.test(password)) score += 10; // No keyboard patterns
        
        // Common password check (simplified)
        const commonPasswords = ['password', '123456', 'qwerty', 'admin', 'welcome'];
        if (!commonPasswords.includes(password.toLowerCase())) score += 10;
        
        // Determine strength level
        let strength;
        if (score >= 90) strength = 'Very Strong';
        else if (score >= 70) strength = 'Strong';
        else if (score >= 50) strength = 'Good';
        else if (score >= 30) strength = 'Fair';
        else if (score >= 10) strength = 'Weak';
        else strength = 'Very Weak';
        
        // Generate feedback
        if (password.length < 8) feedback.push('Password should be at least 8 characters long');
        if (!/[a-z]/.test(password)) feedback.push('Add lowercase letters');
        if (!/[A-Z]/.test(password)) feedback.push('Add uppercase letters');
        if (!/[0-9]/.test(password)) feedback.push('Add numbers');
        if (!/[^A-Za-z0-9]/.test(password)) feedback.push('Add special characters');
        
        return { score, strength, feedback };
    }

    // Generate secure password
    static generatePassword(length = 16, options = { uppercase: true, lowercase: true, numbers: true, symbols: true }) {
        const chars = {
            uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            lowercase: 'abcdefghijklmnopqrstuvwxyz',
            numbers: '0123456789',
            symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
        };
        
        let charPool = '';
        if (options.uppercase) charPool += chars.uppercase;
        if (options.lowercase) charPool += chars.lowercase;
        if (options.numbers) charPool += chars.numbers;
        if (options.symbols) charPool += chars.symbols;
        
        // Ensure at least one character from each selected type
        let password = '';
        if (options.uppercase) password += chars.uppercase[Math.floor(Math.random() * chars.uppercase.length)];
        if (options.lowercase) password += chars.lowercase[Math.floor(Math.random() * chars.lowercase.length)];
        if (options.numbers) password += chars.numbers[Math.floor(Math.random() * chars.numbers.length)];
        if (options.symbols) password += chars.symbols[Math.floor(Math.random() * chars.symbols.length)];
        
        // Fill remaining length with random characters
        for (let i = password.length; i < length; i++) {
            password += charPool[Math.floor(Math.random() * charPool.length)];
        }
        
        // Shuffle the password
        password = password.split('').sort(() => Math.random() - 0.5).join('');
        
        return password;
    }
}

// UI Utility Functions
class SecurityUI {
    // Show loading screen
    static showLoading(message = 'Loading...') {
        if (elements.loadingScreen) {
            elements.loadingScreen.classList.remove('hidden');
            const status = elements.loadingScreen.querySelector('.loading-status');
            if (status) status.textContent = message;
        }
    }

    // Hide loading screen
    static hideLoading() {
        if (elements.loadingScreen) {
            elements.loadingScreen.classList.add('hidden');
        }
    }

    // Update page title
    static updatePageTitle(title, subtitle = '') {
        if (elements.pageTitle) elements.pageTitle.textContent = title;
        if (elements.pageSubtitle && subtitle) elements.pageSubtitle.textContent = subtitle;
    }

    // Add activity log entry
    static addActivityLog(type, title, description) {
        const activity = {
            id: SecurityUtils.generateId('activity_'),
            type,
            title,
            description,
            timestamp: new Date().toISOString(),
            time: new Date().toLocaleTimeString()
        };
        
        securityData.threats.push(activity);
        
        // Update UI
        if (elements.activityLog) {
            const activityItem = document.createElement('div');
            activityItem.className = `activity-item ${type}`;
            activityItem.innerHTML = `
                <div class="activity-icon ${type}">
                    <i class="fas fa-${this.getActivityIcon(type)}"></i>
                </div>
                <div class="activity-content">
                    <div class="activity-title">${title}</div>
                    <div class="activity-desc">${description}</div>
                    <div class="activity-time">${activity.time}</div>
                </div>
            `;
            
            elements.activityLog.insertBefore(activityItem, elements.activityLog.firstChild);
            
            // Limit to 10 items
            if (elements.activityLog.children.length > 10) {
                elements.activityLog.removeChild(elements.activityLog.lastChild);
            }
        }
        
        // Add notification
        SecurityUI.addNotification(type, title, description);
    }

    // Get icon for activity type
    static getActivityIcon(type) {
        const icons = {
            critical: 'exclamation-triangle',
            warning: 'exclamation-circle',
            info: 'info-circle',
            success: 'check-circle',
            scan: 'search',
            threat: 'shield-alt',
            network: 'network-wired'
        };
        return icons[type] || 'info-circle';
    }

    // Add notification
    static addNotification(type, title, message) {
        const notification = {
            id: SecurityUtils.generateId('notif_'),
            type,
            title,
            message,
            timestamp: new Date().toISOString(),
            read: false
        };
        
        securityData.notifications.push(notification);
        
        // Update notification count
        if (elements.notificationCount) {
            const unread = securityData.notifications.filter(n => !n.read).length;
            elements.notificationCount.textContent = unread;
            elements.notificationCount.style.display = unread > 0 ? 'flex' : 'none';
        }
        
        // Update notification list
        SecurityUI.updateNotificationList();
    }

    // Update notification list
    static updateNotificationList() {
        if (!elements.notificationList) return;
        
        elements.notificationList.innerHTML = '';
        
        securityData.notifications.slice(0, 10).forEach(notification => {
            const notificationItem = document.createElement('div');
            notificationItem.className = `notification-item ${notification.type}`;
            notificationItem.innerHTML = `
                <div class="notification-title">
                    <span>${notification.title}</span>
                    <span class="notification-time">${new Date(notification.timestamp).toLocaleTimeString()}</span>
                </div>
                <div class="notification-message">${notification.message}</div>
            `;
            
            elements.notificationList.appendChild(notificationItem);
        });
    }

    // Show toast notification
    static showToast(message, type = 'info') {
        // Create toast container if it doesn't exist
        let toastContainer = document.getElementById('toast-container');
        if (!toastContainer) {
            toastContainer = document.createElement('div');
            toastContainer.id = 'toast-container';
            toastContainer.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 9999;
            `;
            document.body.appendChild(toastContainer);
        }
        
        // Create toast
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.style.cssText = `
            background: ${this.getToastColor(type)};
            color: white;
            padding: 12px 20px;
            border-radius: 8px;
            margin-bottom: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            animation: slideIn 0.3s ease;
        `;
        toast.textContent = message;
        
        toastContainer.appendChild(toast);
        
        // Remove toast after 3 seconds
        setTimeout(() => {
            toast.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    static getToastColor(type) {
        const colors = {
            info: 'linear-gradient(90deg, #64ffda, #9d4edd)',
            success: 'linear-gradient(90deg, #00ff88, #00cc66)',
            warning: 'linear-gradient(90deg, #ffd166, #ffaa00)',
            error: 'linear-gradient(90deg, #ff2e63, #ff0066)'
        };
        return colors[type] || colors.info;
    }

    // Update metrics
    static updateMetrics() {
        // Update critical threats count
        if (elements.criticalThreats) {
            const criticalCount = securityData.threats.filter(t => t.type === 'critical').length;
            elements.criticalThreats.textContent = criticalCount;
        }
        
        // Update protected systems (simulated)
        if (elements.protectedSystems) {
            const protectedCount = Math.floor(Math.random() * 10) + 20; // 20-30 systems
            elements.protectedSystems.textContent = protectedCount;
        }
        
        // Update last scan time
        if (elements.lastScanTime) {
            const scanTimes = ['5m', '12m', '25m', '1h', '2h'];
            const randomTime = scanTimes[Math.floor(Math.random() * scanTimes.length)];
            elements.lastScanTime.textContent = randomTime;
        }
        
        // Update network traffic
        if (elements.networkTraffic) {
            const traffic = Math.floor(Math.random() * 500) + 800; // 800-1300 MB
            elements.networkTraffic.textContent = SecurityUtils.formatBytes(traffic * 1024 * 1024);
        }
        
        // Update health score
        if (elements.healthScore) {
            const score = Math.floor(Math.random() * 10) + 85; // 85-95%
            elements.healthScore.textContent = `${score}%`;
        }
    }

    // Toggle notification center
    static toggleNotificationCenter() {
        const notificationCenter = document.getElementById('notificationCenter');
        if (notificationCenter) {
            notificationCenter.classList.toggle('active');
        }
    }

    // Mark all notifications as read
    static markAllNotificationsRead() {
        securityData.notifications.forEach(notification => {
            notification.read = true;
        });
        
        if (elements.notificationCount) {
            elements.notificationCount.textContent = '0';
            elements.notificationCount.style.display = 'none';
        }
        
        SecurityUI.updateNotificationList();
    }
}

// Initialize utilities
document.addEventListener('DOMContentLoaded', () => {
    // Update time every second
    SecurityUtils.updateTime();
    setInterval(SecurityUtils.updateTime, 1000);
    
    // Initialize with sample data
    SecurityUI.updateMetrics();
    SecurityUI.updateNotificationList();
    
    // Add initial activities
    setTimeout(() => {
        SecurityUI.addActivityLog('info', 'System Initialized', 'Security dashboard is now active');
        SecurityUI.addActivityLog('success', 'Firewall Updated', 'Latest security rules applied');
        SecurityUI.addActivityLog('warning', 'Suspicious Activity', 'Unusual network traffic detected');
        
        // Hide loading screen after 2 seconds
        setTimeout(() => {
            SecurityUI.hideLoading();
        }, 2000);
    }, 1000);
});

// Global utility exports
window.SecurityUtils = SecurityUtils;
window.SecurityUI = SecurityUI;
window.securityData = securityData;
