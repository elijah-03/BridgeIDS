document.addEventListener('DOMContentLoaded', function () {
    // const predictBtn = document.getElementById('predict-btn');
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
                    max: 1
                }
            },
            responsive: true,
            maintainAspectRatio: false
        }
    });

    // Port Helper Logic
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
        "Benign": {
            "Dst Port": 55,
            "Protocol": 17,
            "Hour": 12,
            "Total Fwd Packets": 1,
            "Fwd Packets Length Total": 47,
            "Flow Duration": 74128,
            "Flow IAT Mean": 29462,
            "Fwd Packet Length Max": 46,
            "FIN Flag Count": 0,
            "SYN Flag Count": 0,
            "RST Flag Count": 0,
            "Init Fwd Win Bytes": 0 // Was -2, set to 0
        },
        "DoS": {
            "Dst Port": 82,
            "Protocol": 6,
            "Hour": 13,
            "Total Fwd Packets": 6,
            "Fwd Packets Length Total": 326,
            "Flow Duration": 7000976,
            "Flow IAT Mean": 778626,
            "Fwd Packet Length Max": 367,
            "FIN Flag Count": 1,
            "SYN Flag Count": 2,
            "RST Flag Count": 0,
            "Init Fwd Win Bytes": 26885
        },
        "DDoS": {
            "Dst Port": 82,
            "Protocol": 6,
            "Hour": 19,
            "Total Fwd Packets": 4,
            "Fwd Packets Length Total": 282,
            "Flow Duration": 10090,
            "Flow IAT Mean": 2301,
            "Fwd Packet Length Max": 324,
            "FIN Flag Count": 2,
            "SYN Flag Count": 2,
            "RST Flag Count": 0,
            "Init Fwd Win Bytes": 65544
        },
        "Brute Force": {
            "Dst Port": 23, // Telnet - High confidence (99.7%)
            "Protocol": 6,
            "Hour": 18,
            "Total Fwd Packets": 22,
            "Fwd Packets Length Total": 1926,
            "Flow Duration": 248235.84,
            "Flow IAT Mean": 3919.83,
            "Fwd Packet Length Max": 639.25,
            "FIN Flag Count": 2,
            "SYN Flag Count": 1,
            "RST Flag Count": 0,
            "Init Fwd Win Bytes": 26881
        },
        "Web Attack": {
            "Dst Port": 82,
            "Protocol": 6,
            "Hour": 17,
            "Total Fwd Packets": 208,
            "Fwd Packets Length Total": 57541,
            "Flow Duration": 57385952,
            "Flow IAT Mean": 185049,
            "Fwd Packet Length Max": 680,
            "FIN Flag Count": 2,
            "SYN Flag Count": 2,
            "RST Flag Count": 0,
            "Init Fwd Win Bytes": 8190
        },
        "Bot/Infiltration": {
            "Dst Port": 8048,
            "Protocol": 6,
            "Hour": 15,
            "Total Fwd Packets": 4,
            "Fwd Packets Length Total": 284,
            "Flow Duration": 5520,
            "Flow IAT Mean": 1794,
            "Fwd Packet Length Max": 326,
            "FIN Flag Count": 2,
            "SYN Flag Count": 2,
            "RST Flag Count": 0,
            "Init Fwd Win Bytes": 8190
        }
    };

    // Handle Preset Buttons
    document.querySelectorAll('.preset-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const type = btn.getAttribute('data-type');
            const preset = presets[type];
            if (preset) {
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
                } else {
                    input.value = value;
                    // Update value input if it exists
                    const valInput = document.getElementById(`val-${key}`);
                    if (valInput) {
                        valInput.value = value;
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
                    alert('Error: ' + data.error);
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

                // Update sensitivity analysis if available
                const sensitivityBox = document.getElementById('sensitivity-box');
                const sensitivityText = document.getElementById('sensitivity-text');
                if (data.sensitivity_analysis && data.sensitivity_analysis.length > 0) {
                    const suggestions = data.sensitivity_analysis.map(s => s.description).join('<br>');
                    sensitivityText.innerHTML = suggestions;
                    sensitivityBox.style.display = 'block';
                } else {
                    sensitivityBox.style.display = 'none';
                }

                updateChart(data.probabilities);
                updateInsight(data);
            })
            .catch(error => {
                console.error('Error:', error);
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

    function updateInsight(data) {
        const insightText = document.getElementById('insight-text');

        if (data.insights && data.insights.length > 0) {
            // Use backend-provided insights (Z-scores)
            const drivers = data.insights.map(i => i.description).join(', ');
            let html = `<strong>Key Drivers:</strong> ${drivers}`;

            // Add pattern description if available
            if (data.pattern_description) {
                html += `<br><strong>Pattern:</strong> ${data.pattern_description}`;
            }

            insightText.innerHTML = html;
        } else {
            // Fallback or default message
            insightText.textContent = "Traffic patterns appear normal.";
        }
    }

    // Trigger initial prediction on page load
    predict();
});
