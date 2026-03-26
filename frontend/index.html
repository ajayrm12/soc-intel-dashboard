<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SecOps Intelligence Dashboard</title>

<script src="https://html2canvas.hertzen.com/dist/html2canvas.min.js"></script>

<style>
body {
    margin: 0;
    font-family: 'Segoe UI', sans-serif;
    background: #0a0f1c;
    color: #e0e0e0;
    overflow-x: hidden;
}


body::before {
    content: "";
    position: fixed;
    width: 200%;
    height: 200%;
    background-image:
        linear-gradient(rgba(0,255,150,0.05) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,255,150,0.05) 1px, transparent 1px);
    background-size: 40px 40px;
    animation: moveGrid 15s linear infinite;
    z-index: -2;
}

@keyframes moveGrid {
    from { transform: translate(0,0); }
    to { transform: translate(-200px,-200px); }
}

/* ✨ Floating glow animation */
.glow {
    position: fixed;
    width: 500px;
    height: 500px;
    background: radial-gradient(circle, rgba(0,255,200,0.15), transparent);
    animation: float 10s infinite alternate;
    z-index: -1;
}

.glow:nth-child(1) { top: 10%; left: 10%; }
.glow:nth-child(2) { bottom: 10%; right: 10%; animation-delay: 3s; }

@keyframes float {
    from { transform: translate(0,0); }
    to { transform: translate(50px,50px); }
}

/* 🚨 ALERT MODE */
.alert {
    background: radial-gradient(circle, #330000, #000) !important;
    animation: flash 1s infinite;
}

@keyframes flash {
    0% { filter: brightness(1); }
    50% { filter: brightness(2); }
    100% { filter: brightness(1); }
}

/* Layout */
.container {
    text-align: center;
    padding: 60px 20px;
}

h1 {
    color: #00ffcc;
    font-size: 42px;
    margin-bottom: 10px;
}

/* Input */
input {
    padding: 12px;
    width: 320px;
    border-radius: 8px;
    border: none;
    background: #111827;
    color: white;
}

/* Buttons */
button {
    padding: 12px 20px;
    margin: 8px;
    border: none;
    border-radius: 8px;
    background: #00ffcc;
    color: black;
    font-weight: bold;
    cursor: pointer;
    transition: 0.3s;
}

button:hover {
    background: #00e6b8;
}

/* Cards */
.cards {
    display: flex;
    justify-content: center;
    flex-wrap: wrap;
    gap: 20px;
    margin-top: 40px;
    animation: fadeIn 0.5s ease-in;
}

.card {
    background: rgba(255,255,255,0.05);
    padding: 20px;
    border-radius: 12px;
    width: 260px;
    backdrop-filter: blur(10px);
    border: 1px solid rgba(0,255,200,0.2);
    transition: 0.3s;
}

.card:hover {
    transform: translateY(-6px);
}

.safe { color: #00ff99; }
.danger { color: #ff4d4d; }

/* Loader */
.loader {
    margin-top: 20px;
    display: none;
}

/* Animation */
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(20px);}
    to { opacity: 1; transform: translateY(0);}
}
</style>
</head>

<body>

<div class="glow"></div>
<div class="glow"></div>

<div class="container" id="captureArea">
    <h1>🛡️ SecOps Intelligence</h1>
    <p>Threat Analysis for IP / Domain</p>

    <input id="target" placeholder="Enter IP or domain">
    <br>

    <button onclick="analyze()">Analyze</button>
    <button onclick="capture()">📸 Capture</button>

    <div class="loader" id="loader">⏳ Analyzing...</div>

    <div class="cards" id="results"></div>
</div>

<script>
async function analyze() {
    const target = document.getElementById("target").value;

    if (!target) {
        alert("Enter target!");
        return;
    }

    document.getElementById("loader").style.display = "block";
    document.getElementById("results").innerHTML = "";

    try {
        const res = await fetch("/analyze?target=" + target);
        const data = await res.json();

        document.getElementById("loader").style.display = "none";

        let isDanger = data.virustotal?.malicious > 0;
        let verdict = isDanger ? "⚠️ MALICIOUS" : "✅ SAFE";
        let cls = isDanger ? "danger" : "safe";

        /* 🚨 ALERT BACKGROUND */
        if (isDanger) {
            document.body.classList.add("alert");
        } else {
            document.body.classList.remove("alert");
        }

        document.getElementById("results").innerHTML = `
            <div class="card">
                <h3>🌍 Location</h3>
                <p>${data.geo.country}</p>
                <p>${data.geo.city}</p>
            </div>

            <div class="card">
                <h3>📡 ISP</h3>
                <p>${data.geo.isp}</p>
            </div>

            <div class="card">
                <h3>🛡️ Threat Intel</h3>
                <p class="${cls}"><b>${verdict}</b></p>
                <p>Malicious: ${data.virustotal?.malicious || 0}</p>
                <p>Suspicious: ${data.virustotal?.suspicious || 0}</p>
                <p>Harmless: ${data.virustotal?.harmless || 0}</p>
            </div>

            <div class="card">
                <h3>🌐 Domain Info</h3>
                <p>Age: ${data.domain_age || "N/A"}</p>
            </div>
        `;
    } catch (err) {
        document.getElementById("loader").style.display = "none";
        alert("Error fetching data!");
    }
}

/* 📸 Screenshot */
function capture() {
    html2canvas(document.getElementById("captureArea")).then(canvas => {
        let link = document.createElement('a');
        link.download = 'secops-report.png';
        link.href = canvas.toDataURL();
        link.click();
    });
}

/* Enter key */
document.getElementById("target").addEventListener("keypress", function(e) {
    if (e.key === "Enter") analyze();
});
</script>

</body>
</html>
