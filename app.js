// app.js - Main application controller

document.addEventListener('DOMContentLoaded', function() {
    console.log('Cybersecurity Dashboard initialized');
    
    // Initialize everything
    initNavigation();
    initEventListeners();
    initDashboard();
     
    // Start time updates
    updateTime();
    setInterval(updateTime, 1000);
    
    // Hide loading screen after 2 seconds
    setTimeout(() => {
        window.content.showLoading(false);
    }, 2000);
});

// Navigation
function initNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    const pages = document.querySelectorAll('.page');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Get target page
            const targetPage = this.getAttribute('data-page');
            
            // Update active nav link
            navLinks.forEach(l => l.classList.remove('active'));
            this.classList.add('active');
            
            // Show target page
            pages.forEach(page => page.classList.remove('active'));
            document.getElementById(targetPage).classList.add('active');
            
            // Update page title
            updatePageTitle(targetPage);
            
            // Initialize page-specific content
            initPageContent(targetPage);
        });
    });
}

function updatePageTitle(page) {
    const titles = {
        dashboard: 'Security Dashboard',
        scanner: 'Vulnerability Scanner',
        password: 'Password Analyzer',
        threats: 'Threat Detection',
        network: 'Network Traffic'
    };
    
    const titleElement = document.getElementById('page-title');
    if (titleElement) {
        titleElement.textContent = titles[page] || 'Cybersecurity Dashboard';
    }
}

function initPageContent(page) {
    switch(page) {
        case 'dashboard':
            window.content.drawThreatMap();
            break;
        case 'threats':
            window.content.loadThreats();
            break;
        case 'network':
            window.content.drawNetworkGraph();
            break;
        case 'password':
            // Initialize password analyzer
            const passwordInput = document.getElementById('password-input');
            if (passwordInput) {
                passwordInput.addEventListener('input', function() {
                    window.content.updatePasswordStrengthVisual(this.value);
                });
            }
            
            // Initialize length slider
            const lengthSlider = document.getElementById('length-slider');
            const lengthValue = document.getElementById('length-value');
            if (lengthSlider && lengthValue) {
                lengthSlider.addEventListener('input', function() {
                    lengthValue.textContent = this.value;
                });
            }
            
            // Generate initial password
            window.content.generatePassword();
            break;
    }
}

// Event Listeners
function initEventListeners() {
    // Quick scan button
    const quickScanBtn = document.getElementById('quick-scan');
    if (quickScanBtn) {
        quickScanBtn.addEventListener('click', function() {
            window.content.runScan();
        });
    }
    
    // Password input for real-time analysis
    const passwordInput = document.getElementById('password-input');
    if (passwordInput) {
        passwordInput.addEventListener('input', function() {
            window.content.updatePasswordStrengthVisual(this.value);
        });
    }
    
    // Length slider
    const lengthSlider = document.getElementById('length-slider');
    const lengthValue = document.getElementById('length-value');
    if (lengthSlider && lengthValue) {
        lengthSlider.addEventListener('input', function() {
            lengthValue.textContent = this.value;
        });
    }
    
    // Scan target input - allow Enter key
    const scanTarget = document.getElementById('scan-target');
    if (scanTarget) {
        scanTarget.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                window.content.startScan();
            }
        });
    }
}

// Time display
function updateTime() {
    window.content.updateTime();
}

// Dashboard initialization
function initDashboard() {
    // Add initial activities
    setTimeout(() => {
        window.content.addActivity('info', 'System Online', 'All security systems operational');
        window.content.addActivity('success', 'Firewall Updated', 'Latest security rules applied');
        window.content.addActivity('warning', 'Suspicious Activity', 'Unusual network traffic detected');
        
        // Initialize visualizations
        window.content.drawThreatMap();
        window.content.drawNetworkGraph();
    }, 1000);
    
    // Update metrics periodically
    setInterval(updateMetrics, 30000);
}

function updateMetrics() {
    // Simulate metric updates
    const metrics = document.querySelectorAll('.metric-value');
    metrics.forEach(metric => {
        if (metric.id === 'critical-count') {
            const current = parseInt(metric.textContent);
            const change = Math.random() > 0.7 ? 1 : 0;
            metric.textContent = Math.max(0, current + change);
        }
    });
}

// Initialize dashboard page
initPageContent('dashboard');

// Handle window resize
window.addEventListener('resize', function() {
    window.content.drawThreatMap();
    window.content.drawNetworkGraph();
});
