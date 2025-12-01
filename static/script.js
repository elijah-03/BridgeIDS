/**
 * IDS Control Panel - Main Application Script
 * Handles prediction interface, feature analysis, and visualization
 * @author IDS Team
 * @version 2.0
 */

(function () {
    'use strict';

    // ==================== UTILITY FUNCTIONS ====================

    /**
     * Toast Notification System
     * Displays user-friendly notifications instead of alerts
     */
    const Toast = {
        /**
         * Show a toast notification
         * @param {string} message - Message to display
         * @param {string} type - Type of toast: 'error', 'success', 'info'
         * @param {number} duration - Duration in milliseconds (default: 4000)
         */
        show: function (message, type = 'info', duration = 4000) {
            const container = document.getElementById('toast-container');
            if (!container) return;

            const toast = document.createElement('div');
            toast.className = `toast ${type}`;

            const icons = {
                error: '❌',
                success: '✅',
                info: 'ℹ️'
            };

            toast.innerHTML = `
                <span class="toast-icon">${icons[type] || icons.info}</span>
                <span class="toast-message">${message}</span>
                <span class="toast-close">×</span>
            `;

            container.appendChild(toast);

            // Close button handler
            toast.querySelector('.toast-close').addEventListener('click', () => {
                this.close(toast);
            });

            // Auto-close after duration
            if (duration > 0) {
                setTimeout(() => {
                    this.close(toast);
                }, duration);
            }
        },

        /**
         * Close a toast notification with animation
         * @param {HTMLElement} toast - Toast element to close
         */
        close: function (toast) {
            toast.classList.add('hiding');
            setTimeout(() => {
                toast.remove();
            }, 300);
        }
    };

    /**
     * Error Handler
     * Centralized error handling with user-friendly messages
     */
    const ErrorHandler = {
        /**
         * Handle prediction errors
         * @param {Error|string} error - Error object or message
         */
        handlePredictionError: function (error) {
            console.error('Prediction error:', error);
            const message = typeof error === 'string' ? error :
                error.message || 'Failed to get prediction. Please try again.';
            Toast.show(message, 'error');
        },

        /**
         * Handle feature analysis errors
         * @param {Error|string} error - Error object or message
         */
        handleAnalysisError: function (error) {
            console.error('Analysis error:', error);
            const message = typeof error === 'string' ? error :
                error.message || 'Failed to analyze feature. Please try again.';
            Toast.show(message, 'error');
        },

        /**
         * Handle network errors
         * @param {Error} error - Network error object
         */
        handleNetworkError: function (error) {
            console.error('Network error:', error);
            Toast.show('Network error. Please check your connection and try again.', 'error');
        }
    };

    // ==================== MAIN APPLICATION ====================

    document.addEventListener('DOMContentLoaded', function () {
        const ctx = document.getElementById('predictionChart').getContext('2d');
        const portInput = document.getElementById('Dst Port');
        const portHelper = document.getElementById('port-helper');

        /**
         * Chart.js Initialization
         * Configures the bar chart for displaying prediction probabilities.
         * Uses a fixed set of labels corresponding to the model's classes.
         */
        let predictionChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Benign', 'DoS', 'DDoS', 'Brute Force', 'Web Attack', 'Bot/Infiltration'],
                datasets: [{
                    label: 'Probability',
                    data: [0, 0, 0, 0, 0, 0],
                    backgroundColor: [
                        'rgba(75, 192, 192, 0.6)', // Benign (Green)
                        'rgba(255, 99, 132, 0.6)', // DoS (Red)
                        'rgba(255, 159, 64, 0.6)', // DDoS (Orange)
                        'rgba(153, 102, 255, 0.6)', // Brute Force (Purple)
                        'rgba(54, 162, 235, 0.6)', // Web Attack (Blue)
                        'rgba(255, 206, 86, 0.6)'  // Bot/Infiltration (Yellow)
                    ],
                    borderColor: [
                        'rgba(75, 192, 192, 1)',
                        'rgba(255, 99, 132, 1)',
                        'rgba(255, 159, 64, 1)',
                        'rgba(153, 102, 255, 1)',
                        'rgba(54, 162, 235, 1)',
                        'rgba(255, 206, 86, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 1,
                        title: {
                            display: true,
                            text: 'Probability'
                        }
                    }
                },
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        enabled: true,
                        callbacks: {
                            label: function (context) {
                                return context.dataset.label + ': ' + (context.parsed.y * 100).toFixed(1) + '%';
                            }
                        }
                    }
                }
            }
        });

        /**
         * Port Helper Logic
         * Maps common port numbers to service names
         */
        const portMap = {
            80: "HTTP (Web)",
            443: "HTTPS (Secure Web)",
            21: "FTP (File Transfer)",
            22: "SSH (Secure Shell)",
            23: "Telnet",
            25: "SMTP (Email)",
            53: "DNS",
            3306: "MySQL",
            8080: "HTTP Alt"
        };

        if (portInput) {
            portInput.addEventListener('input', function () {
                const port = parseInt(this.value);
                portHelper.textContent = portMap[port] || "Unknown Service";
            });
        }

        /**
         * Presets Configuration
         * Pre-defined feature values for common attack types and benign traffic.
         * Used to quickly populate the form for demonstration purposes.
         */
        const presets = {
            // Benign Variations
            "Benign_Normal": {
                "Dst Port": 80, "Protocol": 6, "Hour": 12, "Total Fwd Packets": 5, "Fwd Packets Length Total": 500,
                "Flow Duration": 100000, "Flow IAT Mean": 20000, "Fwd Packet Length Max": 100,
                "FIN Flag Count": 0, "SYN Flag Count": 0, "RST Flag Count": 0, "Init Fwd Win Bytes": 8192
            },
            "Benign_High": {
                "Dst Port": 443, "Protocol": 6, "Hour": 14, "Total Fwd Packets": 50, "Fwd Packets Length Total": 50000,
                "Flow Duration": 5000000, "Flow IAT Mean": 100000, "Fwd Packet Length Max": 1400,
                "FIN Flag Count": 0, "SYN Flag Count": 0, "RST Flag Count": 0, "Init Fwd Win Bytes": 65535
            },
            "Benign_SSH": {
                "Dst Port": 22, "Protocol": 6, "Hour": 10, "Total Fwd Packets": 15, "Fwd Packets Length Total": 2000,
                "Flow Duration": 60000000, "Flow IAT Mean": 4000000, "Fwd Packet Length Max": 200,
                "FIN Flag Count": 0, "SYN Flag Count": 0, "RST Flag Count": 0, "Init Fwd Win Bytes": 29200
            },

            // DoS Variations
            "DoS_Slowloris": { // 🟢 100.0% confidence (Real Dataset Sample)
                "Dst Port": 80, "Protocol": 6, "Hour": 15, "Total Fwd Packets": 15, "Fwd Packets Length Total": 2530,
                "Flow Duration": 106588564, "Flow IAT Mean": 6269915, "Fwd Packet Length Max": 230,
                "FIN Flag Count": 0, "SYN Flag Count": 4, "RST Flag Count": 1, "Init Fwd Win Bytes": 26883
            },
            "DoS_Volumetric": { // 🟢 100.0% confidence (Real Dataset Sample: GoldenEye)
                "Dst Port": 80, "Protocol": 6, "Hour": 13, "Total Fwd Packets": 6, "Fwd Packets Length Total": 367,
                "Flow Duration": 7007038, "Flow IAT Mean": 778559, "Fwd Packet Length Max": 367,
                "FIN Flag Count": 1, "SYN Flag Count": 2, "RST Flag Count": 1, "Init Fwd Win Bytes": 26883
            },
            "DoS_Hulk": { // 🟢 100.0% confidence (Real Dataset Sample)
                "Dst Port": 80, "Protocol": 6, "Hour": 17, "Total Fwd Packets": 5, "Fwd Packets Length Total": 352,
                "Flow Duration": 138389, "Flow IAT Mean": 15376, "Fwd Packet Length Max": 352,
                "FIN Flag Count": 2, "SYN Flag Count": 2, "RST Flag Count": 0, "Init Fwd Win Bytes": 26883
            },

            // DDoS Variations
            "DDoS_SYN_Flood": { // 🟢 98.2% confidence (Optimized)
                "Dst Port": 80, "Protocol": 6, "Hour": 18, "Total Fwd Packets": 34438, "Fwd Packets Length Total": 1080667,
                "Flow Duration": 37153779, "Flow IAT Mean": 220548, "Fwd Packet Length Max": 30,
                "FIN Flag Count": 0, "SYN Flag Count": 1, "RST Flag Count": 1, "Init Fwd Win Bytes": 22370
            },
            "DDoS_UDP": {
                "Dst Port": 80, "Protocol": 17, "Hour": 3, "Total Fwd Packets": 36555, "Fwd Packets Length Total": 186086,
                "Flow Duration": 24707613, "Flow IAT Mean": 59758, "Fwd Packet Length Max": 27,
                "FIN Flag Count": 0, "SYN Flag Count": 0, "RST Flag Count": 0, "Init Fwd Win Bytes": 8711
            },
            "DDoS_HTTP_Flood": { // 🟢 100.0% confidence (Real Dataset Sample: LOIC-HTTP)
                "Dst Port": 80, "Protocol": 6, "Hour": 14, "Total Fwd Packets": 5, "Fwd Packets Length Total": 20,
                "Flow Duration": 21257703, "Flow IAT Mean": 2657212, "Fwd Packet Length Max": 20,
                "FIN Flag Count": 1, "SYN Flag Count": 2, "RST Flag Count": 1, "Init Fwd Win Bytes": 8192
            },

            // Brute Force Variations
            "BruteForce_SSH": { // 🟢 100.0% confidence (Real Dataset Sample)
                "Dst Port": 22, "Protocol": 6, "Hour": 18, "Total Fwd Packets": 23, "Fwd Packets Length Total": 1928,
                "Flow Duration": 384601, "Flow IAT Mean": 8546, "Fwd Packet Length Max": 640,
                "FIN Flag Count": 2, "SYN Flag Count": 2, "RST Flag Count": 0, "Init Fwd Win Bytes": 26883
            },
            "BruteForce_FTP": { // 🟡 90.0% confidence (Optimized)
                "Dst Port": 21, "Protocol": 6, "Hour": 18, "Total Fwd Packets": 44, "Fwd Packets Length Total": 115919,
                "Flow Duration": 389615, "Flow IAT Mean": 9109177, "Fwd Packet Length Max": 341,
                "FIN Flag Count": 0, "SYN Flag Count": 1, "RST Flag Count": 1, "Init Fwd Win Bytes": 33161
            },

            // Web Attack (XSS optimized)
            "Web_Attack_XSS": { // 🟢 100.0% confidence (Real Dataset Sample)
                "Dst Port": 80, "Protocol": 6, "Hour": 17, "Total Fwd Packets": 205, "Fwd Packets Length Total": 56083,
                "Flow Duration": 57097125, "Flow IAT Mean": 184780, "Fwd Packet Length Max": 680,
                "FIN Flag Count": 2, "SYN Flag Count": 2, "RST Flag Count": 0, "Init Fwd Win Bytes": 8192
            },

            // Bot
            "Bot_Traffic": {
                "Dst Port": 8080, "Protocol": 17, "Hour": 13, "Total Fwd Packets": 8302, "Fwd Packets Length Total": 415337,
                "Flow Duration": 81409504, "Flow IAT Mean": 6630983, "Fwd Packet Length Max": 1348,
                "FIN Flag Count": 0, "SYN Flag Count": 0, "RST Flag Count": 0, "Init Fwd Win Bytes": 7305
            }
        };

        // Handle Preset Buttons
        document.querySelectorAll('.preset-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const type = btn.getAttribute('data-type');
                const preset = presets[type];
                if (preset) {
                    // Visual feedback
                    btn.classList.add('applied');
                    setTimeout(() => btn.classList.remove('applied'), 500);

                    applyPreset(preset);
                    // Auto-predict after applying preset
                    predict();
                }
            });
        });

        function applyPreset(preset) {
            for (const [key, value] of Object.entries(preset)) {
                const input = document.getElementById(key);
                if (input) {
                    if (input.type === 'checkbox') {
                        input.checked = value > 0;
                        input.dispatchEvent(new Event('change'));
                    } else {
                        input.value = value;
                        input.dispatchEvent(new Event('input'));

                        // Update value input if it exists
                        const valInput = document.getElementById(`val-${key}`);
                        if (valInput) {
                            valInput.value = value;
                            valInput.dispatchEvent(new Event('input'));
                        }
                    }
                }
            }
        }

        // Logarithmic conversion helpers
        function logToLinear(logValue, min, max) {
            // logValue: 0-100 slider position
            // Returns: actual value in range [min, max]
            const minLog = Math.log10(Math.max(1, min));
            const maxLog = Math.log10(max);
            const scale = (maxLog - minLog) / 100;
            return Math.pow(10, minLog + (logValue * scale));
        }

        function linearToLog(value, min, max) {
            // value: actual value
            // Returns: 0-100 slider position
            const minLog = Math.log10(Math.max(1, min));
            const maxLog = Math.log10(max);
            const scale = (maxLog - minLog) / 100;
            return (Math.log10(Math.max(1, value)) - minLog) / scale;
        }

        // Log scale configuration
        const logSliders = {
            'Flow Duration': { min: 1, max: 120000000 },
            'Flow IAT Mean': { min: 1, max: 10000000 },
            'Fwd Packets Length Total': { min: 1, max: 10000000 }
        };

        // Sync sliders and inputs
        document.querySelectorAll('input[type="range"]').forEach(slider => {
            const valInput = document.getElementById(`val-${slider.id}`);
            const isLogScale = slider.hasAttribute('data-log-scale');

            if (valInput) {
                // Initialize slider position based on current value input
                if (isLogScale && logSliders[slider.id]) {
                    const config = logSliders[slider.id];
                    const initialValue = parseFloat(valInput.value);
                    slider.value = linearToLog(initialValue, config.min, config.max);
                }

                // Slider updates input
                slider.addEventListener('input', function () {
                    if (isLogScale && logSliders[slider.id]) {
                        const config = logSliders[slider.id];
                        const actualValue = logToLinear(parseFloat(this.value), config.min, config.max);
                        valInput.value = Math.round(actualValue);
                    } else {
                        valInput.value = this.value;
                    }
                });

                // Input updates slider
                valInput.addEventListener('input', function () {
                    let val = parseFloat(this.value);

                    if (isLogScale && logSliders[slider.id]) {
                        const config = logSliders[slider.id];
                        // Clamp to log range
                        if (val < config.min) val = config.min;
                        if (val > config.max) val = config.max;

                        slider.value = linearToLog(val, config.min, config.max);
                    } else {
                        // Clamp to slider limits (linear)
                        const min = parseFloat(slider.min);
                        const max = parseFloat(slider.max);
                        if (val < min) val = min;
                        if (val > max) val = max;

                        slider.value = val;
                    }
                });
            }
        });

        // Predict Function
        // predictBtn.addEventListener('click', predict);

        // Auto-predict on input change (with debouncing)
        let predictionTimeout;
        const autoPredictDelay = 500; // ms

        // Add listeners to all inputs for auto-prediction
        const allInputs = document.querySelectorAll('.controls-panel input, .controls-panel select');
        allInputs.forEach(input => {
            input.addEventListener('input', () => {
                clearTimeout(predictionTimeout);
                predictionTimeout = setTimeout(() => {
                    predict();
                }, autoPredictDelay);
            });

            input.addEventListener('change', () => {
                clearTimeout(predictionTimeout);
                predictionTimeout = setTimeout(() => {
                    predict();
                }, autoPredictDelay);
            });
        });

        /**
         * Main Prediction Function
         * 1. Collects values from all inputs.
         * 2. Sends data to the /predict endpoint.
         * 3. Updates the UI with the response (prediction, confidence, chart, insights).
         */
        function predict() {
            const features = {};

            // Collect values from inputs
            // We need to collect ALL inputs that match the feature list
            // The backend expects specific feature names.
            // We can iterate over all inputs in the controls panel

            const inputs = document.querySelectorAll('.controls-panel input, .controls-panel select');
            inputs.forEach(input => {
                // Skip log-scale sliders, we'll get the value from the val- input
                if (input.hasAttribute('data-log-scale')) {
                    return;
                }

                let value;
                let featureName = input.id;

                // Handle val- inputs (remove prefix to get actual feature name)
                if (featureName.startsWith('val-')) {
                    featureName = featureName.substring(4);
                }

                if (input.type === 'checkbox') {
                    value = input.checked ? 1 : 0;
                } else {
                    value = parseFloat(input.value);
                }
                features[featureName] = value;
            });

            // Send to backend
            fetch('/predict', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(features)
            })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        ErrorHandler.handlePredictionError(data.error);
                        return;
                    }

                    // Update Prediction Text with color-coding
                    const predictionEl = document.getElementById('prediction-text');
                    predictionEl.textContent = data.prediction;

                    // Color-code based on attack type and confidence
                    const isAttack = data.prediction !== 'Benign';
                    const isLowConf = data.confidence_level === 'Low';

                    predictionEl.className = 'prediction-value';
                    if (isLowConf) {
                        predictionEl.classList.add('low-confidence');
                    } else if (isAttack) {
                        predictionEl.classList.add('high-confidence', 'attack');
                    } else {
                        predictionEl.classList.add('high-confidence', 'benign');
                    }

                    // Update confidence badge
                    const confidenceBadge = document.getElementById('confidence-badge');
                    confidenceBadge.textContent = data.confidence_level + ' Confidence';
                    confidenceBadge.className = `confidence-badge confidence-${data.confidence_level.toLowerCase()}`;

                    // Update timestamp
                    const timestampEl = document.getElementById('timestamp-display');
                    const date = new Date(data.timestamp);
                    timestampEl.textContent = `Analyzed: ${date.toLocaleString()}`;

                    // Update confidence gauge
                    updateConfidenceGauge(data.confidence, data.confidence_level);

                    // Update sensitivity analysis if available
                    const sensitivityBox = document.getElementById('sensitivity-box');
                    const sensitivityText = document.getElementById('sensitivity-text');
                    if (data.sensitivity_analysis && data.sensitivity_analysis.length > 0) {
                        const suggestions = data.sensitivity_analysis.map(s => s.description).join('<br>');
                        sensitivityText.innerHTML = suggestions;
                    } else {
                        sensitivityText.textContent = "No sensitivity analysis available.";
                    }

                    updateChart(data.probabilities);
                    updateInsight(data);
                })
                .catch(error => {
                    ErrorHandler.handlePredictionError(error);
                });
        }

        function updateChart(probabilities) {
            // probabilities is a list of {class: '...', probability: ...}
            // We need to map this to the chart labels order
            const labels = predictionChart.data.labels;
            const chartData = labels.map(label => {
                const item = probabilities.find(d => d.class === label);
                return item ? item.probability : 0;
            });

            predictionChart.data.datasets[0].data = chartData;
            predictionChart.update();
        }

        /**
         * Update confidence gauge visualization
         * @param {number} confidence - Confidence value (0-1)
         * @param {string} level - Confidence level: 'High', 'Medium', 'Low'
         */
        function updateConfidenceGauge(confidence, level) {
            const gaugeContainer = document.getElementById('confidence-gauge-container');
            const gaugeFill = document.getElementById('confidence-gauge-fill');

            if (!gaugeContainer || !gaugeFill) return;

            // Show gauge
            gaugeContainer.style.display = 'block';

            // Update width
            const percentage = (confidence * 100);
            gaugeFill.style.width = percentage + '%';

            // Update color based on level
            gaugeFill.className = 'confidence-gauge-fill ' + level.toLowerCase();
        }

        function updateInsight(data) {
            const insightText = document.getElementById('insight-text');
            const shapContainer = document.getElementById('shap-container');
            const shapPlot = document.getElementById('shap-plot');

            if (data.insights && data.insights.length > 0) {
                // Display insights as a bulleted list for better readability
                let html = '<ul style="margin: 0; padding-left: 20px; line-height: 1.8;">';
                data.insights.forEach(insight => {
                    html += `<li>${insight.description}</li>`;
                });
                html += '</ul>';

                // Add pattern description if available
                if (data.pattern_description) {
                    html += `<p style="margin-top: 15px;"><strong>Pattern:</strong> ${data.pattern_description}</p>`;
                }

                insightText.innerHTML = html;
            } else {
                // Fallback or default message
                insightText.textContent = "Traffic patterns appear normal.";
            }

            // Update SHAP plot
            if (data.shap_plot) {
                shapPlot.src = 'data:image/png;base64,' + data.shap_plot;
                shapPlot.style.display = 'block';
            } else {
                shapPlot.src = ''; // Clear if no plot
                shapPlot.style.display = 'none';
            }
        }

        // Trigger initial prediction on page load
        predict();

        // --- Analysis Feature Implementation ---

        // Modal Elements
        const modal = document.getElementById("analysis-modal");
        const closeModal = document.querySelector(".close-modal");
        const analysisChartCtx = document.getElementById("analysisChart").getContext("2d");
        let analysisChart = null;

        // Close modal when clicking X or outside
        if (closeModal) {
            closeModal.onclick = function () {
                modal.style.display = "none";
            }
        }

        window.onclick = function (event) {
            if (event.target == modal) {
                modal.style.display = "none";
            }
        }

        // Handle Analyze Buttons
        document.querySelectorAll('.analyze-btn').forEach(btn => {
            btn.addEventListener('click', function (e) {
                e.preventDefault(); // Prevent any form submission
                const featureName = this.getAttribute('data-feature');
                analyzeFeature(featureName);
            });
        });

        function analyzeFeature(featureName) {
            // Collect current features
            const currentFeatures = {};
            const inputs = document.querySelectorAll('.controls-panel input, .controls-panel select');

            inputs.forEach(input => {
                if (input.hasAttribute('data-log-scale')) return;

                let name = input.id;
                if (name.startsWith('val-')) name = name.substring(4);

                let value;
                if (input.type === 'checkbox') {
                    value = input.checked ? 1 : 0;
                } else {
                    value = parseFloat(input.value);
                }
                currentFeatures[name] = value;
            });

            // Show loading state
            document.getElementById('analysis-title').textContent = `Analyzing ${featureName}...`;
            document.getElementById('analysis-description').textContent = "Generating partial dependence plot...";
            modal.style.display = "block";

            // Call Backend
            fetch('/analyze_feature', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    feature_name: featureName,
                    current_features: currentFeatures
                })
            })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        ErrorHandler.handleAnalysisError(data.error);
                        return;
                    }
                    renderAnalysisChart(data);
                })
                .catch(error => {
                    ErrorHandler.handleAnalysisError(error);
                    document.getElementById('analysis-description').textContent = "Error generating analysis.";
                });
        }

        function renderAnalysisChart(data) {
            document.getElementById('analysis-title').textContent = `Impact of ${data.feature_name}`;

            const description = `This chart shows how the probability of <strong>${data.target_class}</strong> changes as <strong>${data.feature_name}</strong> varies, while keeping all other features constant.`;
            document.getElementById('analysis-description').innerHTML = description;

            if (analysisChart) {
                analysisChart.destroy();
            }

            analysisChart = new Chart(analysisChartCtx, {
                type: 'line',
                data: {
                    labels: data.x_values.map(v => {
                        // Format labels nicely
                        if (Math.abs(v) > 1000) return (v / 1000).toFixed(1) + 'k';
                        if (Number.isInteger(v)) return v;
                        return v.toFixed(2);
                    }),
                    datasets: [{
                        label: `Probability of ${data.target_class}`,
                        data: data.y_values,
                        borderColor: 'rgba(54, 162, 235, 1)',
                        backgroundColor: 'rgba(54, 162, 235, 0.2)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 4,
                        pointHoverRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    onClick: function (evt, elements) {
                        if (elements.length > 0) {
                            const index = elements[0].index;
                            const xValue = data.x_values[index];

                            // Update the input field
                            const inputId = data.feature_name;
                            const input = document.getElementById(inputId);
                            const valInput = document.getElementById(`val-${inputId}`);

                            if (input) {
                                if (input.type === 'checkbox') {
                                    input.checked = xValue > 0.5;
                                } else {
                                    // Handle log scale sliders
                                    if (input.hasAttribute('data-log-scale')) {
                                        // Update the val- input first
                                        if (valInput) {
                                            valInput.value = xValue;
                                            valInput.dispatchEvent(new Event('input'));
                                        }
                                    } else {
                                        input.value = xValue;
                                        input.dispatchEvent(new Event('input'));
                                    }
                                }

                                // Trigger prediction
                                predict();

                                // Re-analyze to update the "Current Value" marker
                                analyzeFeature(data.feature_name);
                            }
                        }
                    },
                    plugins: {
                        annotation: {
                            annotations: {
                                line1: {
                                    type: 'line',
                                    xMin: data.x_values.indexOf(data.x_values.reduce((prev, curr) => Math.abs(curr - data.current_value) < Math.abs(prev - data.current_value) ? curr : prev)),
                                    xMax: data.x_values.indexOf(data.x_values.reduce((prev, curr) => Math.abs(curr - data.current_value) < Math.abs(prev - data.current_value) ? curr : prev)),
                                    borderColor: 'red',
                                    borderWidth: 2,
                                    label: {
                                        content: 'Current Value',
                                        enabled: true,
                                        position: 'top'
                                    }
                                }
                            }
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 1,
                            title: {
                                display: true,
                                text: 'Probability'
                            }
                        },
                        x: {
                            title: {
                                display: true,
                                text: data.feature_name
                            }
                        }
                    }
                }
            });
        }

        // Update SHAP Highlighting
        const originalUpdateInsight = updateInsight;
        updateInsight = function (data) {
            // Render Counterfactuals (Safety Prescriptions)
            const cfSection = document.getElementById('counterfactuals-section');
            if (data.counterfactuals && data.counterfactuals.length > 0) {
                let html = '<div class="safety-prescription">';
                html += '<h5>Benign Prescription</h5>';
                html += '<ul class="prescription-list">';

                data.counterfactuals.forEach(cf => {
                    html += `<li>
                    <span class="action">${cf.action}</span>
                    <span class="impact">(${cf.impact})</span>
                </li>`;
                });

                html += '</ul></div>';
                cfSection.innerHTML = html;
                cfSection.style.display = 'block';
            } else {
                cfSection.style.display = 'none';
            }

            // Render Local Rule
            const ruleContainer = document.getElementById('global-rules-tree');
            if (data.local_rule) {
                renderRuleTree([data.local_rule], ruleContainer);
            } else {
                ruleContainer.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--text-muted);">No matching rule found.</div>';
            }

            originalUpdateInsight(data); // Call original function

            // Apply SHAP highlighting
            if (data.shap_contributions) {
                const inputs = document.querySelectorAll('.controls-panel input, .controls-panel select');
                inputs.forEach(input => {
                    // Clear previous highlights
                    input.classList.remove('input-highlight-high', 'input-highlight-medium', 'input-highlight-benign');

                    let featureName = input.id;
                    if (featureName.startsWith('val-')) featureName = featureName.substring(4);

                    const contribution = data.shap_contributions[featureName];

                    if (contribution !== undefined) {
                        // Contribution is normalized -1 to 1 (approx)
                        // Positive = contributes to predicted class
                        // Negative = contributes AGAINST predicted class

                        const absContrib = Math.abs(contribution);

                        if (data.prediction !== 'Benign') {
                            // For attacks:
                            // Positive contribution = Bad (Red)
                            // Negative contribution = Good (Green/Benign)

                            if (contribution > 0.1) {
                                if (absContrib > 0.5) input.classList.add('input-highlight-high');
                                else input.classList.add('input-highlight-medium');
                            } else if (contribution < -0.1) {
                                input.classList.add('input-highlight-benign');
                            }
                        } else {
                            // For Benign:
                            // Positive contribution = Good (Green)
                            // Negative contribution = Bad (Red - pushing towards attack)

                            if (contribution > 0.1) {
                                input.classList.add('input-highlight-benign');
                            } else if (contribution < -0.1) {
                                if (absContrib > 0.5) input.classList.add('input-highlight-high');
                                else input.classList.add('input-highlight-medium');
                            }
                        }
                    }
                });
            }
        };

    });

    // --- Tab Handling ---
    window.switchTab = function (tabName) {
        // Update buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
            if (btn.textContent.toLowerCase().includes(tabName.replace('global', 'global rules'))) {
                btn.classList.add('active');
            }
        });

        // Update content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.style.display = 'none';
            content.classList.remove('active');
        });

        let activeId = '';
        if (tabName === 'insights') activeId = 'insights-box';
        else if (tabName === 'sensitivity') activeId = 'sensitivity-box';
        else if (tabName === 'shap') activeId = 'shap-container';
        else if (tabName === 'global') {
            activeId = 'global-rules-box';
            // No need to load global rules anymore, they come with prediction
        }

        const activeEl = document.getElementById(activeId);
        if (activeEl) {
            activeEl.style.display = 'block';
            activeEl.classList.add('active');
        }
    };

    // Global rules loading removed in favor of local rules per prediction

    function renderRuleTree(rules, container) {
        let html = '<ul class="tree">';

        // Helper to render a single path
        function renderPath(rulePath) {
            let pathHtml = '<li class="rule-path">';
            pathHtml += '<div class="rule-conditions">';

            rulePath.rules.forEach((condition, index) => {
                const isLast = index === rulePath.rules.length - 1;

                // Use the description directly if it exists (for SHAP-based rules)
                // This gives us natural language like "High connection duration (57.1 sec)"
                if (condition.description) {
                    pathHtml += `<span class="condition">
                    <span class="feature">${condition.description}</span>
                </span>`;
                } else {
                    // Fallback to old format for surrogate rules
                    pathHtml += `<span class="condition">
                    <span class="feature">${condition.feature}</span> 
                    <span class="operator">${condition.operator}</span> 
                    <span class="value">${condition.value.toFixed(2)}</span>
                </span>`;
                }
                if (!isLast) pathHtml += ' <span class="logic">AND</span> ';
            });

            pathHtml += '</div>';

            // Prediction
            const confidencePct = (rulePath.confidence * 100).toFixed(0);
            let predClass = 'pred-benign';
            if (rulePath.prediction !== 'Benign') predClass = 'pred-attack';

            pathHtml += `<div class="rule-result ${predClass}">
            <span class="arrow">→</span>
            <span class="prediction">${rulePath.prediction}</span>
            <span class="confidence">(${confidencePct}%)</span>
        </div>`;

            pathHtml += '</li>';
            return pathHtml;
        }

        rules.forEach(rule => {
            html += renderPath(rule);
        });


        html += '</ul>';
        container.innerHTML = html;
    }

    // Expose necessary functions to window object for HTML onclick handlers
    window.switchTab = switchTab;

    // Export Toast globally for potential use in other scripts
    window.Toast = Toast;

    // ==================== TAB HANDLING ====================

    /**
     * Switch between different information tabs
     * @param {string} tabName - Name of tab to switch to: 'insights', 'sensitivity', 'shap', 'global'
     */
    function switchTab(tabName) {
        // Update buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
            if (btn.textContent.toLowerCase().includes(tabName.replace('global', 'local rule').toLowerCase())) {
                btn.classList.add('active');
            }
        });

        // Update content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.style.display = 'none';
            content.classList.remove('active');
        });

        let activeId = '';
        if (tabName === 'insights') activeId = 'insights-box';
        else if (tabName === 'sensitivity') activeId = 'sensitivity-box';
        else if (tabName === 'shap') activeId = 'shap-container';
        else if (tabName === 'global') {
            activeId = 'global-rules-box';
        }

        const activeEl = document.getElementById(activeId);
        if (activeEl) {
            activeEl.style.display = 'block';
            activeEl.classList.add('active');
        }
    }

})(); // End of IIFE
