// SentinelLite Dashboard Frontend Logic

const API_BASE = ""; // Relative URLs

document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("uploadForm");
    const fileInput = document.getElementById("fileInput");
    const loadingDiv = document.getElementById("loading");
    const resultsDiv = document.getElementById("results");
    
    // Load scan history on page load
    loadHistory();
    
    // Handle file upload
    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        
        if (!fileInput.files.length) {
            alert("Please select a file");
            return;
        }
        
        const file = fileInput.files[0];
        const formData = new FormData();
        formData.append("file", file);
        
        // Show loading, hide previous results
        loadingDiv.classList.remove("hidden");
        resultsDiv.classList.add("hidden");
        
        try {
            const response = await fetch("/scan", {
                method: "POST",
                body: formData
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || "Scan failed");
            }
            
            const report = await response.json();
            displayResults(report);
            loadHistory(); // Refresh history after scan
            
        } catch (error) {
            console.error("Upload error:", error);
            alert(`Error: ${error.message}`);
        } finally {
            loadingDiv.classList.add("hidden");
        }
    });
    
    function displayResults(report) {
        // Show results container
        resultsDiv.classList.remove("hidden");
        
        // Set verdict badge
        const verdictBadge = document.getElementById("verdictBadge");
        const verdict = report.verdict.toLowerCase();
        verdictBadge.textContent = `Verdict: ${report.verdict}`;
        verdictBadge.className = `verdict ${verdict}`;
        
        // Fill details
        document.getElementById("filename").textContent = report.filename;
        document.getElementById("sha256").textContent = report.sha256;
        document.getElementById("riskScore").textContent = report.risk_score;
        document.getElementById("entropy").textContent = report.entropy;
        
        // Detection reasons
        const reasonsList = document.getElementById("reasons");
        reasonsList.innerHTML = "";
        report.detection_reasons.forEach(reason => {
            const li = document.createElement("li");
            li.textContent = reason;
            reasonsList.appendChild(li);
        });
        
        // YARA matches
        const yaraDiv = document.getElementById("yaraMatches");
        const yaraList = document.getElementById("yaraList");
        if (report.yara_matches && report.yara_matches.length > 0) {
            yaraDiv.classList.remove("hidden");
            yaraList.innerHTML = "";
            report.yara_matches.forEach(rule => {
                const li = document.createElement("li");
                li.textContent = rule;
                yaraList.appendChild(li);
            });
        } else {
            yaraDiv.classList.add("hidden");
        }
        
        // PE details
        const peDiv = document.getElementById("peDetails");
        if (report.pe_analysis.is_pe) {
            peDiv.classList.remove("hidden");
            const suspicious = report.pe_analysis.suspicious_imports || [];
            document.getElementById("suspiciousImports").textContent = 
                suspicious.length ? suspicious.join(", ") : "None detected";
            document.getElementById("compileTime").textContent = 
                report.pe_analysis.compile_time || "Unknown";
        } else {
            peDiv.classList.add("hidden");
        }
        
        // Scroll to results
        resultsDiv.scrollIntoView({ behavior: "smooth" });
    }
    
    async function loadHistory() {
        const historyContainer = document.getElementById("historyList");
        try {
            const response = await fetch("/history?limit=15");
            if (!response.ok) throw new Error("Failed to load history");
            
            const history = await response.json();
            
            if (history.length === 0) {
                historyContainer.innerHTML = "<p>No scans yet. Upload a file to get started.</p>";
                return;
            }
            
            historyContainer.innerHTML = "";
            history.forEach(item => {
                const div = document.createElement("div");
                div.className = "history-item";
                
                const filename = document.createElement("span");
                filename.className = "filename";
                filename.textContent = item.filename;
                
                const verdictSpan = document.createElement("span");
                verdictSpan.className = `verdict-badge ${item.verdict.toLowerCase()}`;
                verdictSpan.textContent = item.verdict;
                
                const scoreSpan = document.createElement("span");
                scoreSpan.className = "score";
                scoreSpan.textContent = `Score: ${item.risk_score}`;
                
                const dateSpan = document.createElement("span");
                dateSpan.className = "date";
                dateSpan.textContent = new Date(item.timestamp).toLocaleString();
                
                div.appendChild(filename);
                div.appendChild(verdictSpan);
                div.appendChild(scoreSpan);
                div.appendChild(dateSpan);
                
                // Add click to view full report
                div.style.cursor = "pointer";
                div.addEventListener("click", () => viewReport(item.id));
                
                historyContainer.appendChild(div);
            });
        } catch (error) {
            console.error("History load error:", error);
            historyContainer.innerHTML = "<p>Error loading history.</p>";
        }
    }
    
    async function viewReport(scanId) {
        try {
            const response = await fetch(`/report/${scanId}`);
            if (!response.ok) throw new Error("Report not found");
            const report = await response.json();
            displayResults(report);
        } catch (error) {
            alert("Could not load report: " + error.message);
        }
    }
});