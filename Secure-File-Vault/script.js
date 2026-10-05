"use strict";


/* =========================================
   ELEMENTS
========================================= */

const navItems = document.querySelectorAll(".nav-item");
const sections = document.querySelectorAll(".section");

const pageTitle = document.getElementById("pageTitle");

const uploadBox = document.getElementById("uploadBox");
const fileInput = document.getElementById("fileInput");
const chooseFileBtn = document.getElementById("chooseFileBtn");
const selectedFile = document.getElementById("selectedFile");

const scanResult = document.getElementById("scanResult");

const totalScans = document.getElementById("totalScans");
const safeFiles = document.getElementById("safeFiles");
const flaggedFiles = document.getElementById("flaggedFiles");
const averageRisk = document.getElementById("averageRisk");

const postureScore = document.getElementById("postureScore");
const postureTitle = document.getElementById("postureTitle");
const postureText = document.getElementById("postureText");

const resultFileName = document.getElementById("resultFileName");
const riskBadge = document.getElementById("riskBadge");

const riskScore = document.getElementById("riskScore");
const riskCircle = document.getElementById("riskCircle");
const riskTitle = document.getElementById("riskTitle");
const riskDescription = document.getElementById("riskDescription");

const analysisType = document.getElementById("analysisType");
const analysisSize = document.getElementById("analysisSize");
const analysisExtension = document.getElementById("analysisExtension");
const analysisHash = document.getElementById("analysisHash");

const indicatorsList = document.getElementById("indicatorsList");

const downloadReport = document.getElementById("downloadReport");
const scanAnother = document.getElementById("scanAnother");

const historyList = document.getElementById("historyList");
const clearHistory = document.getElementById("clearHistory");

const toast = document.getElementById("toast");


/* =========================================
   STORAGE
========================================= */

const STORAGE_KEY = "secureVaultHistory";

let scanHistory =
    JSON.parse(localStorage.getItem(STORAGE_KEY)) || [];

let currentAnalysis = null;


/* =========================================
   NAVIGATION
========================================= */

const titles = {
    dashboard: "Security Dashboard",
    scanner: "File Security Scanner",
    history: "Scan History",
    about: "About SecureVault"
};


function showSection(sectionId) {

    sections.forEach(section => {
        section.classList.remove("active");
    });

    navItems.forEach(item => {
        item.classList.remove("active");
    });

    const target =
        document.getElementById(sectionId);

    const nav =
        document.querySelector(
            `.nav-item[data-section="${sectionId}"]`
        );

    if (target) {
        target.classList.add("active");
    }

    if (nav) {
        nav.classList.add("active");
    }

    pageTitle.textContent =
        titles[sectionId] || "SecureVault";

    window.scrollTo({
        top: 0,
        behavior: "smooth"
    });
}


navItems.forEach(item => {

    item.addEventListener("click", () => {

        const section =
            item.dataset.section;

        showSection(section);

    });

});


document.querySelectorAll("[data-go]").forEach(button => {

    button.addEventListener("click", () => {

        showSection(button.dataset.go);

    });

});


/* =========================================
   FILE PICKER
========================================= */

chooseFileBtn.addEventListener("click", event => {

    event.preventDefault();

    event.stopPropagation();

    fileInput.click();

});


uploadBox.addEventListener("click", event => {

    if (
        event.target.closest(".choose-btn") ||
        event.target.closest(".file-selected")
    ) {
        return;
    }

    fileInput.click();

});


fileInput.addEventListener("change", () => {

    const file = fileInput.files[0];

    if (!file) {
        return;
    }

    handleFile(file);

});


/* =========================================
   DRAG & DROP
========================================= */

uploadBox.addEventListener("dragover", event => {

    event.preventDefault();

    uploadBox.classList.add("dragging");

});


uploadBox.addEventListener("dragleave", () => {

    uploadBox.classList.remove("dragging");

});


uploadBox.addEventListener("drop", event => {

    event.preventDefault();

    uploadBox.classList.remove("dragging");

    const file =
        event.dataTransfer.files[0];

    if (!file) {
        return;
    }

    handleFile(file);

});


/* =========================================
   HANDLE FILE
========================================= */

async function handleFile(file) {

    showSelectedFile(file);

    showToast("Analyzing file...");

    await analyzeFile(file);

}


/* =========================================
   SELECTED FILE UI
========================================= */

function showSelectedFile(file) {

    selectedFile.innerHTML = `

        <div class="file-selected">

            <div class="file-icon">
                ▣
            </div>

            <div class="file-info">

                <strong>
                    ${escapeHTML(file.name)}
                </strong>

                <small>
                    ${formatFileSize(file.size)}
                    • ${escapeHTML(file.type || "Unknown type")}
                </small>

            </div>

        </div>

    `;

}


/* =========================================
   FILE ANALYSIS
========================================= */

async function analyzeFile(file) {

    scanResult.classList.remove("hidden");

    const extension =
        getExtension(file.name);

    const lowerName =
        file.name.toLowerCase();

    const mime =
        file.type || "Unknown";

    let score = 0;

    const indicators = [];


    /* Dangerous extensions */

    const dangerousExtensions = [

        "exe",
        "scr",
        "bat",
        "cmd",
        "com",
        "msi",
        "vbs",
        "vbe",
        "js",
        "jse",
        "ps1",
        "psm1",
        "jar",
        "hta",
        "wsf",
        "wsh",
        "lnk",
        "reg"

    ];


    const riskyExtensions = [

        "zip",
        "rar",
        "7z",
        "iso",
        "img",
        "dll",
        "apk",
        "docm",
        "xlsm",
        "pptm"

    ];


    if (dangerousExtensions.includes(extension)) {

        score += 45;

        indicators.push({
            type: "danger",
            title: "High-risk extension",
            text:
                `.${extension} can contain executable or script content.`
        });

    } else if (riskyExtensions.includes(extension)) {

        score += 20;

        indicators.push({
            type: "warning",
            title: "Potentially risky format",
            text:
                `.${extension} may contain active or compressed content.`
        });

    } else {

        indicators.push({
            type: "safe",
            title: "Extension appears normal",
            text:
                `.${extension || "none"} is not on the high-risk list.`
        });

    }


    /* Suspicious filename */

    const suspiciousWords = [

        "crack",
        "keygen",
        "hack",
        "payload",
        "malware",
        "virus",
        "trojan",
        "stealer",
        "ransom",
        "password",
        "free_money",
        "activator",
        "injector"

    ];


    const suspiciousName =
        suspiciousWords.some(word =>
            lowerName.includes(word)
        );


    if (suspiciousName) {

        score += 25;

        indicators.push({
            type: "danger",
            title: "Suspicious filename",
            text:
                "The filename contains a security-sensitive keyword."
        });

    } else {

        indicators.push({
            type: "safe",
            title: "Filename looks normal",
            text:
                "No known suspicious filename patterns were found."
        });

    }


    /* Double extension */

    const dotCount =
        (file.name.match(/\./g) || []).length;


    if (dotCount >= 2) {

        score += 15;

        indicators.push({
            type: "warning",
            title: "Multiple extensions detected",
            text:
                "Multiple file extensions can sometimes be used to disguise file types."
        });

    } else {

        indicators.push({
            type: "safe",
            title: "No suspicious double extension",
            text:
                "The filename does not contain multiple extension layers."
        });

    }


    /* File size */

    const maxSize =
        100 * 1024 * 1024;

    if (file.size > maxSize) {

        score += 15;

        indicators.push({
            type: "warning",
            title: "Large file size",
            text:
                "The file is larger than the recommended analysis threshold."
        });

    } else {

        indicators.push({
            type: "safe",
            title: "File size is acceptable",
            text:
                "The file size is within the normal analysis range."
        });

    }


    /* MIME */

    if (
        mime === "application/x-msdownload" ||
        mime === "application/x-msdos-program"
    ) {

        score += 20;

        indicators.push({
            type: "danger",
            title: "Executable MIME type",
            text:
                `Browser reported MIME type: ${mime}`
        });

    } else {

        indicators.push({
            type: "safe",
            title: "MIME type checked",
            text:
                `Detected type: ${mime}`
        });

    }


    /* Clamp */

    score =
        Math.min(100, score);


    /* SHA-256 */

    const hash =
        await calculateSHA256(file);


    currentAnalysis = {

        fileName: file.name,

        size: file.size,

        mime,

        extension,

        score,

        hash,

        timestamp:
            new Date().toISOString(),

        indicators

    };


    renderAnalysis(currentAnalysis);

    saveScan(currentAnalysis);

}


/* =========================================
   SHA-256
========================================= */

async function calculateSHA256(file) {

    try {

        const buffer =
            await file.arrayBuffer();

        const hashBuffer =
            await crypto.subtle.digest(
                "SHA-256",
                buffer
            );

        const hashArray =
            Array.from(
                new Uint8Array(hashBuffer)
            );

        return hashArray
            .map(byte =>
                byte.toString(16).padStart(2, "0")
            )
            .join("");

    } catch (error) {

        console.error(error);

        return "Unavailable";

    }

}


/* =========================================
   RENDER RESULT
========================================= */

function renderAnalysis(data) {

    const level =
        getRiskLevel(data.score);


    resultFileName.textContent =
        data.fileName;


    riskScore.textContent =
        data.score;


    riskTitle.textContent =
        level.title;


    riskDescription.textContent =
        level.description;


    riskBadge.textContent =
        level.label;


    riskBadge.className =
        `risk-badge ${level.className}`;


    riskCircle.style.stroke =
        level.color;


    const circumference =
        314;

    const offset =
        circumference -
        (data.score / 100) *
        circumference;

    riskCircle.style.strokeDashoffset =
        offset;


    analysisType.textContent =
        data.mime;

    analysisSize.textContent =
        formatFileSize(data.size);

    analysisExtension.textContent =
        data.extension
            ? `.${data.extension}`
            : "None";

    analysisHash.textContent =
        data.hash;


    indicatorsList.innerHTML =
        data.indicators
            .map(indicator => `

                <div class="indicator ${indicator.type}">

                    <div class="indicator-icon">

                        ${
                            indicator.type === "safe"
                                ? "✓"
                                : indicator.type === "warning"
                                    ? "!"
                                    : "×"
                        }

                    </div>

                    <div>

                        <strong>
                            ${escapeHTML(indicator.title)}
                        </strong>

                        <small>
                            ${escapeHTML(indicator.text)}
                        </small>

                    </div>

                </div>

            `)
            .join("");


    updateDashboard();

    renderHistory();

}


/* =========================================
   RISK LEVEL
========================================= */

function getRiskLevel(score) {

    if (score >= 60) {

        return {

            label: "HIGH RISK",

            className: "high",

            title: "High risk detected",

            description:
                "Multiple suspicious characteristics were detected. Treat this file carefully and verify its source before opening it.",

            color: "#ff5576"

        };

    }


    if (score >= 30) {

        return {

            label: "SUSPICIOUS",

            className: "suspicious",

            title: "Suspicious characteristics found",

            description:
                "The file contains one or more characteristics that deserve additional investigation.",

            color: "#ffc857"

        };

    }


    return {

        label: "SAFE",

        className: "safe",

        title: "File appears low risk",

        description:
            "No major suspicious indicators were detected by the local heuristic analysis.",

        color: "#38e29a"

    };

}


/* =========================================
   HISTORY
========================================= */

function saveScan(data) {

    scanHistory.unshift(data);

    scanHistory =
        scanHistory.slice(0, 30);

    localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify(scanHistory)
    );

    updateDashboard();

    renderHistory();

}


function renderHistory() {

    if (!scanHistory.length) {

        historyList.innerHTML = `

            <div class="empty-history">

                <div>

                    <strong>
                        No scans yet
                    </strong>

                    <p>
                        Your previous file analyses will appear here.
                    </p>

                </div>

            </div>

        `;

        return;

    }


    historyList.innerHTML =
        scanHistory
            .map(item => {

                const level =
                    getRiskLevel(item.score);

                return `

                    <div class="history-item">

                        <div class="history-name">

                            <strong>
                                ${escapeHTML(item.fileName)}
                            </strong>

                            <small>
                                ${formatDate(item.timestamp)}
                                •
                                ${formatFileSize(item.size)}
                            </small>

                        </div>

                        <div class="history-risk">
                            ${item.score}%
                        </div>

                        <div
                            class="history-status ${level.className}"
                        >
                            ${level.label}
                        </div>

                    </div>

                `;

            })
            .join("");

}


/* =========================================
   DASHBOARD
========================================= */

function updateDashboard() {

    const total =
        scanHistory.length;

    const safe =
        scanHistory.filter(
            item => item.score < 30
        ).length;

    const flagged =
        scanHistory.filter(
            item => item.score >= 30
        ).length;

    const average =
        total
            ? Math.round(
                scanHistory.reduce(
                    (sum, item) =>
                        sum + item.score,
                    0
                ) / total
            )
            : 0;


    totalScans.textContent =
        total;

    safeFiles.textContent =
        safe;

    flaggedFiles.textContent =
        flagged;

    averageRisk.textContent =
        `${average}%`;


    const posture =
        Math.max(
            0,
            100 - average
        );


    postureScore.textContent =
        posture;


    if (!total) {

        postureTitle.textContent =
            "Scanner Ready";

        postureText.textContent =
            "No suspicious files have been detected yet.";

        return;

    }


    if (average >= 60) {

        postureTitle.textContent =
            "High Attention Required";

        postureText.textContent =
            "Recent scans show elevated security risk.";

    } else if (average >= 30) {

        postureTitle.textContent =
            "Review Recommended";

        postureText.textContent =
            "Some scanned files contain suspicious characteristics.";

    } else {

        postureTitle.textContent =
            "Good Security Posture";

        postureText.textContent =
            "Recent files have generally shown low risk.";

    }

}


/* =========================================
   DOWNLOAD REPORT
========================================= */

downloadReport.addEventListener(
    "click",
    () => {

        if (!currentAnalysis) {

            showToast(
                "Run a scan first."
            );

            return;

        }


        const level =
            getRiskLevel(
                currentAnalysis.score
            );


        const report = `

SECUREVAULT
FILE SECURITY ASSESSMENT
========================================

File Name:
${currentAnalysis.fileName}

File Size:
${formatFileSize(currentAnalysis.size)}

MIME Type:
${currentAnalysis.mime}

Extension:
.${currentAnalysis.extension || "none"}

SHA-256:
${currentAnalysis.hash}

Risk Score:
${currentAnalysis.score}/100

Assessment:
${level.label}

${level.description}

SECURITY INDICATORS
========================================

${currentAnalysis.indicators
    .map(
        item =>
            `[${item.type.toUpperCase()}] ${item.title}
${item.text}`
    )
    .join("\n\n")}

========================================

Generated by SecureVault
Local File Security Analysis Platform

Note:
This report is based on heuristic client-side
analysis and is not a replacement for a full
antivirus, sandbox, or threat intelligence scan.

        `.trim();


        const blob =
            new Blob(
                [report],
                {
                    type: "text/plain"
                }
            );


        const url =
            URL.createObjectURL(blob);


        const link =
            document.createElement("a");

        link.href = url;

        link.download =
            `SecureVault-${sanitizeFileName(
                currentAnalysis.fileName
            )}-Report.txt`;

        document.body.appendChild(link);

        link.click();

        link.remove();

        URL.revokeObjectURL(url);

        showToast(
            "Security report downloaded."
        );

    }
);


/* =========================================
   SCAN ANOTHER
========================================= */

scanAnother.addEventListener(
    "click",
    () => {

        fileInput.value = "";

        selectedFile.innerHTML = "";

        scanResult.classList.add(
            "hidden"
        );

        currentAnalysis = null;

        showSection("scanner");

    }
);


/* =========================================
   CLEAR HISTORY
========================================= */

clearHistory.addEventListener(
    "click",
    () => {

        if (!scanHistory.length) {

            showToast(
                "History is already empty."
            );

            return;

        }


        const confirmed =
            confirm(
                "Clear all SecureVault scan history?"
            );


        if (!confirmed) {
            return;
        }


        scanHistory = [];

        localStorage.removeItem(
            STORAGE_KEY
        );

        renderHistory();

        updateDashboard();

        showToast(
            "Scan history cleared."
        );

    }
);


/* =========================================
   HELPERS
========================================= */

function getExtension(filename) {

    const parts =
        filename.split(".");

    if (
        parts.length < 2 ||
        !parts[parts.length - 1]
    ) {
        return "";
    }

    return parts[
        parts.length - 1
    ].toLowerCase();

}


function formatFileSize(bytes) {

    if (bytes === 0) {
        return "0 Bytes";
    }

    const units = [
        "Bytes",
        "KB",
        "MB",
        "GB"
    ];

    const index =
        Math.floor(
            Math.log(bytes) /
            Math.log(1024)
        );

    return (
        bytes /
        Math.pow(1024, index)
    ).toFixed(2)
    + " "
    + units[index];

}


function formatDate(date) {

    return new Date(date)
        .toLocaleString(
            "en-US",
            {
                dateStyle: "medium",
                timeStyle: "short"
            }
        );

}


function sanitizeFileName(name) {

    return name
        .replace(
            /[^a-z0-9._-]/gi,
            "_"
        );

}


function escapeHTML(value) {

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");

}


function showToast(message) {

    toast.textContent =
        message;

    toast.classList.add("show");

    clearTimeout(
        window.secureVaultToast
    );

    window.secureVaultToast =
        setTimeout(
            () => {

                toast.classList.remove(
                    "show"
                );

            },
            2500
        );

}


/* =========================================
   INITIALIZE
========================================= */

renderHistory();

updateDashboard();

showSection("dashboard");