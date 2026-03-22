document.addEventListener("DOMContentLoaded", () => {
  const runScanBtn = document.getElementById("runScanBtn");
  const targetInput = document.getElementById("targetInput");
  const resultDiv = document.getElementById("scan-result");
  const downloadBtn = document.getElementById("downloadBtn");

  if (!runScanBtn || !targetInput || !resultDiv) {
    console.error("Check your HTML IDs: runScanBtn, targetInput, scan-result must exist.");
    return;
  }

  // RUN SCAN BUTTON
  runScanBtn.addEventListener("click", async () => {
    const target = targetInput.value.trim();

    if (!target) {
      alert("Please enter a domain or IP.");
      return;
    }

    resultDiv.innerHTML = "<p>Running scan... Please wait ⏳</p>";

    try {
      const response = await fetch("/run-scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ target: target })
      });

      const data = await response.json();

      if (data.error) {
        resultDiv.innerHTML = `<p style="color:red;">${data.error}</p>`;
        return;
      }

      resultDiv.innerHTML = "";

      function createCard(title, content) {
        const card = document.createElement("div");
        card.classList.add("card");

        card.style.border = "1px solid #333";
        card.style.padding = "10px";
        card.style.margin = "10px 0";
        card.style.backgroundColor = "#f9f9f9";

        const heading = document.createElement("h3");
        heading.textContent = title;
        card.appendChild(heading);

        if (Array.isArray(content)) {
          if (content.length === 0) {
            const p = document.createElement("p");
            p.textContent = "None found";
            card.appendChild(p);
          } else {
            const ul = document.createElement("ul");
            content.forEach(item => {
              const li = document.createElement("li");
              li.textContent = item;
              ul.appendChild(li);
            });
            card.appendChild(ul);
          }
        } else if (typeof content === "object") {
          Object.entries(content).forEach(([key, value]) => {
            const p = document.createElement("p");
            p.innerHTML = `<strong>${key}:</strong> ${value}`;
            card.appendChild(p);
          });
        } else {
          const p = document.createElement("p");
          p.textContent = content;
          card.appendChild(p);
        }

        return card;
      }

      const targetInfo = {
        "Domain": data.target,
        "IP": data.ip,
        "Website Status": data.website_status,
        "Detected OS": data.detected_os,
        "SSL Expiry": data.ssl_expiry,
        "Domain Creation": data.domain_creation
      };

      resultDiv.appendChild(createCard("Target Info", targetInfo));
      resultDiv.appendChild(createCard("Open Ports", data.open_ports));
      resultDiv.appendChild(createCard("Missing Security Headers", data.missing_headers));
      resultDiv.appendChild(createCard("Hidden Directories", data.hidden_dirs));
      resultDiv.appendChild(createCard("Cookie Issues", data.cookie_issues));
      resultDiv.appendChild(createCard("Detected CVEs", data.cves));
      resultDiv.appendChild(createCard("Ads & Media Detected", data.ad_results));

      alert("Scan completed ✅");

    } catch (error) {
      console.error(error);
      resultDiv.innerHTML = "<p style='color:red;'>Scan failed ❌</p>";
    }
  });

  // DOWNLOAD BUTTON
  if (downloadBtn) {
    downloadBtn.addEventListener("click", () => {
      window.location.href = "/download-report";
    });
  }
});