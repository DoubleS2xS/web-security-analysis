// Хранилище данных текущего сеанса для отправки в ИИ
let currentScanData = {
    domain: "",
    open_ports: [],
    headers: {},
    scripts: {},
    shodan: {}
};

document.addEventListener("DOMContentLoaded", () => {
    // Dark Mode логика
    const darkModeToggle = document.getElementById("dark-mode-toggle");
    const body = document.body;
    
    // Проверка сохраненной настройки
    if (localStorage.getItem("dark-mode") === "enabled") {
        body.classList.add("dark-mode");
        if(darkModeToggle) darkModeToggle.textContent = "☀️ Light Mode";
    }

    if (darkModeToggle) {
        darkModeToggle.addEventListener("click", () => {
            body.classList.toggle("dark-mode");
            const isDarkMode = body.classList.contains("dark-mode");
            darkModeToggle.textContent = isDarkMode ? "☀️ Light Mode" : "🌙 Dark Mode";
            localStorage.setItem("dark-mode", isDarkMode ? "enabled" : "disabled");
        });
    }
});

// Основная форма сканирования
const scanForm = document.getElementById("scan-form");
if (scanForm) {
    scanForm.addEventListener("submit", async function (event) {
        event.preventDefault();

        const domainInput = document.getElementById("domain");
        const startPortInput = document.getElementById("start-port");
        const endPortInput = document.getElementById("end-port");
        const actionSelect = document.getElementById("action");
        const resultDiv = document.getElementById("result-content");

        const domain = domainInput.value;
        const action = actionSelect.value;
        
        // Обновляем домен в памяти для ИИ
        currentScanData.domain = domain;
        
        resultDiv.textContent = "Scanning... please wait.";

        try {
            let response, result;

            if (action === "ports") {
                const startPort = startPortInput.value ? parseInt(startPortInput.value) : 1;
                const endPort = endPortInput.value ? parseInt(endPortInput.value) : 1024;

                response = await fetch("/scan_ports", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ domain, start_port: startPort, end_port: endPort })
                });
                result = await response.json();
                
                if (response.ok) {
                    resultDiv.textContent = "Open Ports: " + result.open_ports.join(", ");
                    // Сохраняем порты для ИИ
                    currentScanData.open_ports = result.open_ports;
                } else {
                    resultDiv.textContent = "Error: " + result.error;
                }
            } 
            else if (action === "headers") {
                response = await fetch("/analyze", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ domain, action: "headers" })
                });
                result = await response.json();
                
                if (response.ok) {
                    let headersText = "";
                    if (result.headers) {
                        for (const [key, value] of Object.entries(result.headers)) {
                            headersText += `${key}: ${value}\n`;
                        }
                        // Сохраняем хедеры для ИИ
                        currentScanData.headers = result.headers;
                    }
                    resultDiv.textContent = headersText || "No headers found.";
                    
                    // Сохраняем Shodan данные попутно
                    if (result.shodan) currentScanData.shodan = result.shodan;
                } else {
                    resultDiv.textContent = "Error: " + (result.message || "Failed");
                }
            }
            else if (action === "search_scripts") {
                response = await fetch("/analyze", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ domain, action: "search_scripts" })
                });
                result = await response.json();
                
                if (response.ok) {
                    const cgi = result.cgi_scripts || [];
                    const js = result.js_scripts || [];
                    resultDiv.textContent = `CGI Scripts (${cgi.length}):\n${cgi.join("\n")}\n\nJS Scripts (${js.length}):\n${js.join("\n")}`;
                    
                    // Сохраняем скрипты для ИИ
                    currentScanData.scripts = { cgi_scripts: cgi, js_scripts: js };
                    if (result.shodan) currentScanData.shodan = result.shodan;
                } else {
                    resultDiv.textContent = "Error: " + (result.error || "Failed");
                }
            }
            
            // Если Shodan еще не подгрузился, пробуем подгрузить отдельно
            if (!currentScanData.shodan.IP) {
                 fetch("/analyze", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ domain, action: "shodan" })
                })
                .then(r => r.json())
                .then(d => {
                    if(d.shodan) {
                        document.getElementById("shodan-content").textContent = JSON.stringify(d.shodan, null, 2);
                        currentScanData.shodan = d.shodan;
                    }
                })
                .catch(err => console.error(err));
            } else {
                // Если уже есть, просто отобразим
                document.getElementById("shodan-content").textContent = JSON.stringify(currentScanData.shodan, null, 2);
            }

        } catch (error) {
            resultDiv.textContent = "Request failed: " + error.message;
        }
    });
}

// === ЛОГИКА КНОПКИ AI ===
const aiBtn = document.getElementById("ai-scan-btn");
if (aiBtn) {
    aiBtn.addEventListener("click", async () => {
        const aiBox = document.getElementById("ai-result-content");
        aiBox.style.display = "block";
        aiBox.textContent = "🤔 ИИ анализирует данные... Подождите (15-20 сек)...";

        if (!currentScanData.domain) {
            aiBox.textContent = "⚠️ Сначала выполните сканирование домена (порты или заголовки), чтобы собрать данные для ИИ.";
            return;
        }

        try {
            const response = await fetch("/get_ai_report", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(currentScanData)
            });
            const data = await response.json();
            
            if (data.report) {

                aiBox.textContent = data.report;
            } else {
                aiBox.textContent = "Не удалось получить ответ от ИИ.";
            }
        } catch (e) {
            aiBox.textContent = "Ошибка соединения: " + e.message;
        }
    });
}

// Загрузка истории
async function loadHistory() {
    const historyContainer = document.getElementById("history-content");
    if (!historyContainer) return;

    try {
        const response = await fetch("/history");
        const history = await response.json();

        if (history.length === 0) {
            historyContainer.innerHTML = "<p>No scan history available.</p>";
        } else {
            historyContainer.innerHTML = history
                .map(entry => `<p><strong>${entry.domain}</strong>  ${entry.action}  ${entry.timestamp}</p>`)
                .join("");
        }
    } catch (e) {
        console.error("History load error", e);
    }
}
window.onload = loadHistory;

// === TABS LOGIC ===
window.openTab = function(evt, tabName) {
    const tabContents = document.getElementsByClassName("tab-content");
    for (let i = 0; i < tabContents.length; i++) {
        tabContents[i].style.display = "none";
    }
    const tabBtns = document.getElementsByClassName("tab-btn");
    for (let i = 0; i < tabBtns.length; i++) {
        tabBtns[i].style.background = "transparent";
        tabBtns[i].classList.remove("active");
    }
    document.getElementById(tabName).style.display = "block";
    let bg = tabName === 'dast-tab' ? '#0069d9' : '#222';
    evt.currentTarget.style.background = bg;
    evt.currentTarget.classList.add("active");
}

// === SAST LOGIC ===
const sastForm = document.getElementById("sast-form");
if (sastForm) {
    sastForm.addEventListener("submit", async function(e) {
        e.preventDefault();
        const githubUrl = document.getElementById("github-url").value;
        const zipFile = document.getElementById("zip-file").files[0];
        const statusDiv = document.getElementById("sast-status");
        
        if (!githubUrl && !zipFile) {
            statusDiv.textContent = "Please provide a GitHub URL or upload a ZIP file.";
            return;
        }

        statusDiv.textContent = "Scanning source code... This may take a few minutes depending on the repository size.";
        document.getElementById("sast-results-body").innerHTML = `<tr><td colspan="6" style="padding: 15px; text-align: center;">Scanning...</td></tr>`;

        try {
            let response;
            if (zipFile) {
                const formData = new FormData();
                formData.append("file", zipFile);
                response = await fetch("/scan_code", {
                    method: "POST",
                    body: formData
                });
            } else {
                response = await fetch("/scan_code", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ github_url: githubUrl })
                });
            }

            const result = await response.json();
            if (response.ok) {
                statusDiv.textContent = `Scan Complete! Validated ${result.validation.total_validated} vulnerabilities (Confirmed: ${result.validation.confirmed}, False Positives: ${result.validation.false_positives}, Needs Review: ${result.validation.needs_review}).`;
                renderSastResults(result.vulnerabilities);
            } else {
                statusDiv.textContent = "Error: " + (result.error || "Unknown error occurred");
            }
        } catch (error) {
            statusDiv.textContent = "Request failed: " + error.message;
        }
    });
}

function renderSastResults(vulnerabilities) {
    const tbody = document.getElementById("sast-results-body");
    if (!vulnerabilities || vulnerabilities.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="padding: 15px; text-align: center;">No vulnerabilities found. System is secure!</td></tr>`;
        return;
    }

    tbody.innerHTML = "";
    vulnerabilities.forEach(vuln => {
        const severityColor = vuln.adjusted_severity === 'Critical' ? '#dc3545' : 
                              vuln.adjusted_severity === 'High' ? '#fd7e14' : 
                              vuln.adjusted_severity === 'Medium' ? '#ffc107' : '#28a745';
        
        const statusColor = vuln.status === 'Confirmed' ? '#dc3545' : 
                            vuln.status === 'False Positive' ? '#28a745' : '#17a2b8';

        let actionButtons = "";
        if (vuln.status === 'Needs Human Review') {
            actionButtons = `
                <button onclick="updateVulnStatus(${vuln.id}, 'Approved')" style="background: #dc3545; padding: 5px; font-size: 0.8rem; margin-bottom: 5px; width: 100%;">Approve</button>
                <button onclick="updateVulnStatus(${vuln.id}, 'Rejected')" style="background: #28a745; padding: 5px; font-size: 0.8rem; width: 100%;">Reject</button>
            `;
        } else {
            actionButtons = `<span style="font-size:0.9rem; color: #555;">${vuln.analyst_decision || '-'}</span>`;
        }

        const row = document.createElement("tr");
        row.innerHTML = `
            <td style="padding: 10px; border: 1px solid #ddd; max-width: 200px; word-wrap: break-word;">
                <strong>${vuln.filepath}</strong><br>Line: ${vuln.line_number}
            </td>
            <td style="padding: 10px; border: 1px solid #ddd;">
                <strong>${vuln.vulnerability_type}</strong> (${vuln.cwe_id})<br>
                <small>${vuln.description}</small>
            </td>
            <td style="padding: 10px; border: 1px solid #ddd; color: ${severityColor}; font-weight: bold; text-align: center;">
                ${vuln.adjusted_severity}
            </td>
            <td style="padding: 10px; border: 1px solid #ddd; text-align: center;">
                ${vuln.confidence_score}%
            </td>
            <td style="padding: 10px; border: 1px solid #ddd; color: ${statusColor}; font-weight: bold; text-align: center;" id="status-${vuln.id}">
                ${vuln.status}
            </td>
            <td style="padding: 10px; border: 1px solid #ddd; text-align: center; vertical-align: middle;" id="action-${vuln.id}">
                ${actionButtons}
            </td>
        `;
        tbody.appendChild(row);
    });
}

window.updateVulnStatus = async function(vulnId, decision) {
    if (!confirm(`Are you sure you want to mark this as ${decision}?`)) return;

    try {
        const response = await fetch(`/sast/vulnerability/${vulnId}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ decision: decision, comment: "Reviewed via web UI" })
        });
        const result = await response.json();
        
        if (response.ok) {
            const statusCell = document.getElementById(`status-${vulnId}`);
            const actionCell = document.getElementById(`action-${vulnId}`);
            
            statusCell.textContent = result.new_status;
            statusCell.style.color = result.new_status === 'Confirmed' ? '#dc3545' : '#28a745';
            
            actionCell.innerHTML = `<span style="font-size:0.9rem; color: #555;">${decision}</span>`;
            alert("Status updated successfully!");
        } else {
            alert("Error: " + result.error);
        }
    } catch (e) {
        alert("Failed to update status: " + e.message);
    }
}
