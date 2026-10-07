document.addEventListener('DOMContentLoaded', () => {
    // Initialize Dashboard Charts if elements exist
    if (document.getElementById('riskChart') || document.getElementById('policyChart')) {
        fetchDashboardStats();
    }

    // Initialize Prediction Form Handler if element exists
    const predictionForm = document.getElementById('predictionForm');
    if (predictionForm) {
        predictionForm.addEventListener('submit', handlePredictionSubmit);
    }
});

/* ---------------------------------------------------------------------------
 * Dashboard Analytics Functions
 * --------------------------------------------------------------------------- */
function fetchDashboardStats() {
    fetch('/api/stats')
        .then(response => {
            if (!response.ok) throw new Error('Failed to fetch analytics data');
            return response.json();
        })
        .then(data => {
            renderRiskChart(data.risk_distribution);
            renderPolicyChart(data.policy_breakdown);
        })
        .catch(error => console.error('Error loading dashboard stats:', error));
}

function renderRiskChart(riskData) {
    const riskCtx = document.getElementById('riskChart');
    if (!riskCtx) return;

    const lowRisk = riskData.find(item => item.is_fraud === 0)?.count || 0;
    const highRisk = riskData.find(item => item.is_fraud === 1)?.count || 0;

    new Chart(riskCtx.getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['Legitimate (Low Risk)', 'Fraudulent (High Risk)'],
            datasets: [{
                data: [lowRisk, highRisk],
                backgroundColor: ['#10b981', '#f43f5e'],
                borderColor: '#0b1020',
                borderWidth: 3,
                hoverOffset: 8
            }]
        },
        options: {
            responsive: true,
            cutout: '68%',
            plugins: {
                legend: { position: 'bottom', labels: { color: '#94a3b8', usePointStyle: true } }
            }
        }
    });
}

function renderPolicyChart(policyData) {
    const policyCtx = document.getElementById('policyChart');
    if (!policyCtx) return;

    const labels = policyData.map(item => item.policy_type);
    const counts = policyData.map(item => item.count);

    new Chart(policyCtx.getContext('2d'), {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Claims Evaluated',
                data: counts,
                backgroundColor: '#6366f1',
                hoverBackgroundColor: '#22d3ee',
                borderRadius: 8
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: { beginAtZero: true, ticks: { stepSize: 1, color: '#94a3b8' }, grid: { color: 'rgba(148,163,184,0.08)' } },
                x: { ticks: { color: '#94a3b8' }, grid: { display: false } }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

/* ---------------------------------------------------------------------------
 * Claim Assessment / Prediction Form Handler
 * --------------------------------------------------------------------------- */
function handlePredictionSubmit(e) {
    e.preventDefault();

    const form = e.target;
    const formData = new FormData(form);
    const payload = {};

    formData.forEach((value, key) => {
        payload[key] = value;
    });

    const submitBtn = document.getElementById('submitBtn');
    const resultBox = document.getElementById('resultBox');
    const resultStatus = document.getElementById('resultStatus');
    const resultScore = document.getElementById('resultScore');

    // UI Loading State
    submitBtn.disabled = true;
    submitBtn.innerText = 'Analyzing Claim...';

    fetch('/predict', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`Server returned HTTP status ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        // Reset Button
        submitBtn.disabled = false;
        submitBtn.innerText = 'Assess Fraud Risk';

        // Update Text
        resultStatus.innerText = data.result;
        resultScore.innerText = `${data.fraud_probability}% Risk Level`;

        // Apply Styling and Show Box
        if (data.prediction === 1) {
            resultBox.className = 'prediction-result-box danger';
        } else {
            resultBox.className = 'prediction-result-box success';
        }
        resultBox.style.display = 'block';
    })
    .catch(error => {
        submitBtn.disabled = false;
        submitBtn.innerText = 'Assess Fraud Risk';
        alert('An error occurred during evaluation. Please check the browser/server console.');
        console.error('Prediction Error:', error);
    });
}