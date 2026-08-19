const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const path = require('path');
const axios = require('axios'); 

const app = express();
app.use(express.json());
app.use(cors());

// Explicitly serve the frontend so Render's health check passes instantly
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Serve any other static assets
app.use(express.static(__dirname));

// 1. Indian PII Regex Parser
const PATTERNS = {
    aadhaar: /\b[2-9]{1}\d{3}\s?\d{4}\s?\d{4}\b/g,
    pan: /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g,
    upi: /\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b/g,
    phone: /\b(?:\+91[\-\s]?)?[6-9]\d{9}\b/g,
    email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g
};

function scanText(text) {
    const results = {};
    if (!text) return results;
    for (const [key, regex] of Object.entries(PATTERNS)) {
        const matches = text.match(regex);
        if (matches) {
            results[key] = [...new Set(matches)]; // Remove duplicates
        }
    }
    return results;
}

// 2. Risk Scorer (Scam Vulnerability Index)
const WEIGHTS = {
    aadhaar: 0.35,
    pan: 0.25,
    phone: 0.20,
    upi: 0.12,
    email: 0.08
}; 

function calculateScamIndex(exposures) {
    let rawScore = 0.0;
    const detectedFactors = [];
    for (const [piiType, items] of Object.entries(exposures)) {
        if (WEIGHTS[piiType]) {
            const count = items.length;
            rawScore += WEIGHTS[piiType] * Math.min(count, 3);
            detectedFactors.push(`${piiType.toUpperCase()} exposed (${count})`);
        }
    }
    const normalizedScore = Math.min(10.0, Math.round(rawScore * 100) / 10);
    let riskLevel = 'LOW';
    
    if (normalizedScore >= 7.0) riskLevel = 'CRITICAL';
    else if (normalizedScore >= 4.0) riskLevel = 'MEDIUM';
    
    return {
        score: normalizedScore,
        level: riskLevel,
        factors: detectedFactors
    };
}

// 3. DPDP Section 12 Notice Template Generator
function generateDPDPNotice(userName, userEmail, companyName, dpoEmail, piiSummary, refId) {
return `
NOTICE FOR ERASURE OF PERSONAL DATA
Under Section 12 of the Digital Personal Data Protection Act (DPDP Act), 2023

To: Data Protection Officer / Grievance Officer
Entity: ${companyName}
Email: ${dpoEmail}

Sir/Madam,
I, ${userName} (Data Principal), hereby issue this formal notice requesting 
erasure of my Personal Data held by ${companyName} (Data Fiduciary).

1. EXPOSED/PROCESSED DATA PARAMETERS:
- Specific Identifier(s): ${piiSummary}
- Reference Breach ID / Exposure Alert: ${refId}

2. LEGAL DEMAND: 
Pursuant to Section 12 of the DPDP Act 2023, I hereby request you to erase 
all personal data specified above and direct any Data Processors engaged by 
you to erase such personal data.

Please confirm compliance within 72 hours.

Regards,
${userName}
Contact: ${userEmail}
`;
}

// ================= API ROUTES =================

// Threat & OSINT Scanning Route
app.post('/api/v1/scan', async (req, res) => {
    const { userId, rawPayload } = req.body;
    
    // 1. Run local Regex
    const exposures = scanText(rawPayload);
    let externalBreaches = [];
    
    // 2. Simulated OSINT Internet Search
    if (exposures.email && exposures.email.length > 0) {
        const targetEmail = exposures.email[0];
        
        try {
            console.log(`[OSINT Engine] Searching dark web for: ${targetEmail}`);
            await new Promise(resolve => setTimeout(resolve, 1200)); 
            
            externalBreaches = [
                { source: "Telegram Dump #2841", date: "2026-08-10" },
                { source: "TechCorp Database Leak", date: "2024-03-15" }
            ];
            
        } catch (error) {
            console.error("OSINT API Search failed:", error.message);
        }
    }

    // 3. Calculate Score
    const scamIndex = calculateScamIndex(exposures);
    
    // 4. Return Results
    res.json({
        status: 'success',
        user_id: userId,
        exposures_found: exposures,
        internet_breaches_found: externalBreaches.length,
        breach_details: externalBreaches,
        scam_index: scamIndex
    });
});

// DPDP Notice Generation Route
app.post('/api/v1/dpdp/generate-notice', (req, res) => {
    const { userName, userEmail, companyName, dpoEmail, piiTypes, exposureRef } = req.body;
    const piiSummary = (piiTypes || []).join(', ');
    const noticeText = generateDPDPNotice(userName, userEmail, companyName, dpoEmail, piiSummary, exposureRef);
    
    res.json({
        status: 'generated',
        notice_document: noticeText
    });
});

// PRODUCTION FIX: Let Render dynamically assign the port, otherwise fallback to 3000
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});