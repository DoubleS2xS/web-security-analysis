document.addEventListener("DOMContentLoaded", () => {
    const darkModeToggle = document.getElementById("dark-mode-toggle");
    const body = document.body;

    // saved mode preference
    const savedMode = localStorage.getItem("dark-mode");
    if (savedMode === "enabled") {
        body.classList.add("dark-mode");
        darkModeToggle.textContent = "☀️ Light Mode";
    }

    // Toggle dark mode
    darkModeToggle.addEventListener("click", () => {
        body.classList.toggle("dark-mode");
        const isDarkMode = body.classList.contains("dark-mode");
        darkModeToggle.textContent = isDarkMode ? "☀️ Light Mode" : "🌙 Dark Mode";


        localStorage.setItem("dark-mode", isDarkMode ? "enabled" : "disabled");
    });
});

document.getElementById("scan-form").addEventListener("submit", async function (event) {
    event.preventDefault();

    const domain = document.getElementById("domain").value;
    const startPort = document.getElementById("start-port").value;
    const endPort = document.getElementById("end-port").value;
    const action = document.getElementById("action").value;

    try {
        let response;
        let result;

        if (action === "ports") {
            response = await fetch("/scan_ports", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    domain: domain,
                    start_port: parseInt(startPort),
                    end_port: parseInt(endPort)
                })
            });

            result = await response.json();

            if (response.ok) {
                document.getElementById("result-content").textContent =
                    "Open Ports: " + result.open_ports.join(", ");
            } else {
                document.getElementById("result-content").textContent =
                    "Error: " + result.error;
            }
        } else if (action === "search_scripts") {
            response = await fetch("/analyze", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ domain, action }),
            });

            result = await response.json();

            if (response.ok) {
                document.getElementById("result-content").textContent =
                    `CGI Scripts:\n${result.cgi_scripts.join("\n")}\n\nJS Scripts:\n${result.js_scripts.join("\n")}`;
            } else {
                document.getElementById("result-content").textContent = result.error || "An error occurred";
            }
        } else if (action === "headers") {
            response = await fetch("/analyze", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    domain: domain,
                    action: "headers"
                })
            });

            result = await response.json();

            if (response.ok) {
                const headers = result.headers;
                let headersText = "";
                for (const [key, value] of Object.entries(headers)) {
                    headersText += `${key}: ${value}\n`;
                }
                document.getElementById("result-content").textContent = headersText;
            } else {
                document.getElementById("result-content").textContent =
                    "Error: " + (result.error || "Failed to analyze headers");
            }
        } else {
            document.getElementById("result-content").textContent =
                "This action is not implemented yet.";
        }
    } catch (error) {
        document.getElementById("result-content").textContent =
            "Request failed: " + error.message;
    }

    // Shodan Test
    try {
        const shodanResponse = await fetch("/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ domain, action: "shodan" })
        });

        const shodanResult = await shodanResponse.json();

        if (shodanResponse.ok) {
            document.getElementById("shodan-content").textContent =
                JSON.stringify(shodanResult.shodan, null, 2);
        } else {
            document.getElementById("shodan-content").textContent = "Error fetching Shodan data.";
        }
    } catch (error) {
        document.getElementById("shodan-content").textContent = "Error: " + error.message;
    }
});

document.getElementById("scan-form").addEventListener("submit", async (event) => {
    event.preventDefault();

    const domain = document.getElementById("domain").value;
    const startPort = document.getElementById("start-port").value;
    const endPort = document.getElementById("end-port").value;
    const action = document.getElementById("action").value;

    const response = await fetch("/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, start_port: startPort, end_port: endPort, action }),
    });

    const data = await response.json();
    document.getElementById("result-content").innerHTML = `<p>${data.result}</p>`;
});

async function loadHistory() {
    const response = await fetch("/history");
    const history = await response.json();
    const historyContainer = document.getElementById("history-content"); // Используем правильный контейнер для истории

    if (history.length === 0) {
        historyContainer.innerHTML = "<p>No scan history available.</p>";
    } else {
        historyContainer.innerHTML = history
            .map(
                (entry) =>
                    `<p><strong>Domain:</strong> ${entry.domain} | <strong>Action:</strong> ${entry.action} | <strong>Time:</strong> ${entry.timestamp}</p>`
            )
            .join("");
    }
}

window.onload = loadHistory;
