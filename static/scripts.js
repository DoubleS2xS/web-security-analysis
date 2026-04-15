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
                .map(entry => `<p><strong>${entry.domain}</strong> | ${entry.action} | ${entry.timestamp}</p>`)
                .join("");
        }
    } catch (e) {
        console.error("History load error", e);
    }
}
window.onload = loadHistory;