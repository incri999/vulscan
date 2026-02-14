let latestResults = null;

function startScan() {
    const target = document.getElementById("target").value;
    const resultsDiv = document.getElementById("results");
    const progressBar = document.getElementById("progressBar");
    const progressContainer = document.getElementById("progressContainer");
    const downloadSection = document.getElementById("downloadSection");

    if (!target) {
        alert("Enter a website.");
        return;
    }

    resultsDiv.innerHTML = "";
    downloadSection.classList.add("hidden");
    progressContainer.classList.remove("hidden");
    progressBar.style.width = "0%";

    let progress = 0;
    const interval = setInterval(() => {
        progress += 8;
        progressBar.style.width = progress + "%";
        if (progress >= 90) clearInterval(interval);
    }, 200);

    fetch("/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target })
    })
    .then(res => res.json())
    .then(data => {
        latestResults = data;
        progressBar.style.width = "100%";
        setTimeout(() => progressContainer.classList.add("hidden"), 500);

        resultsDiv.innerHTML = `
            <div class="card">
                <div class="card-header">
                    <h3>Scan Results for ${data.target}</h3>
                </div>
            </div>

            ${generateCard("SQL Injection", data.sql_injection)}
            ${generateCard("Cross-Site Scripting (XSS)", data.xss)}
            ${generateCard("Security Headers", data.security_headers)}
            ${generateCard("Port Scan", data.port_scan)}
        `;

        downloadSection.classList.remove("hidden");
    })
    .catch(err => {
        progressContainer.classList.add("hidden");
        resultsDiv.innerHTML = "<p style='color:red;'>Scan failed.</p>";
    });
}

function generateCard(title, data) {
    return `
        <div class="card">
            <div class="card-header">
                <h4>${title}</h4>
                <span class="badge ${data.risk.toLowerCase()}">${data.risk}</span>
            </div>
            <p>${data.details}</p>
        </div>
    `;
}

function downloadReport() {
    if (!latestResults) return;

    const reportContent = `
VulScan Vulnerability Report
=============================

Target: ${latestResults.target}

SQL Injection:
Risk: ${latestResults.sql_injection.risk}
Details: ${latestResults.sql_injection.details}

XSS:
Risk: ${latestResults.xss.risk}
Details: ${latestResults.xss.details}

Security Headers:
Risk: ${latestResults.security_headers.risk}
Details: ${latestResults.security_headers.details}

Port Scan:
Risk: ${latestResults.port_scan.risk}
Details: ${latestResults.port_scan.details}
`;

    const blob = new Blob([reportContent], { type: "text/plain" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "vulscan_report.txt";
    link.click();
}
