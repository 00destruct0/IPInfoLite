# LLM Analysis with the IPinfo Lite PowerShell Module 

This directory contains prompt templates, examples, and best practices for analyzing IP geolocation data using Large Language Models (LLMs) like Claude, ChatGPT, and Gemini.

## Best Practices

### Security Considerations

**Data Sensitivity and Privacy Considerations:**
- If the dataset includes customer IPs, ensure handling aligns with your organization’s privacy policy
- Be aware of applicable regional data protection laws (e.g., GDPR, CCPA) that may govern the processing or external sharing of IP address data
- Consider data minimization: export only the IPs necessary for analysis
- When in doubt, consult with your organization's Data Protection Officer (DPO) or legal counsel


**Threat Intelligence Sharing:**
- LLM-based analysis is well-suited for internal exploration and investigation
- Be cautious when sharing LLM-generated threat intelligence externally without validation
- Always verify critical findings using authoritative sources before taking action

**Compliance:**
- Ensure LLM usage complies with organizational data handling policies
- Some industries restrict uploading network data to cloud-based LLM services
- Consider on-premise or self-hosted LLM solutions for highly sensitive environments

*This guidance is informational and does not replace legal or compliance review where required*

### Data Preparation

**Recommended Practices:**
- Export recent, relevant data (last 24-48 hours for active threats)
- Include context in your prompts (what generated these IPs, when, etc.)
- Filter data before export when working with large datasets (LLM context limits)
- Use descriptive filenames (e.g., `ssh_bruteforce_2025-01-18.jsonl`)

**Practices to Avoid:**
- Upload of extremely large files (>100MB); consider sampling
- Mix of unrelated data sources without explaining the context
- Expectation of LLMs to track changes without providing historical data


## Example Workflows

### Workflow 1: Application-Layer DDoS Infrastructure Analysis

*Scenario: Ongoing Layer 7 DDoS activity targeting an application endpoint. The objective is to understand the network infrastructure characteristics of the source IPs to inform mitigation decisions.*

**Analysis Goals:**
- Summarize the geographic distribution of source IPs (country and continent level)
- Identify concentration or dispersion across ASNs and network operators
- Highlight infrastructure patterns consistent with hosting providers versus consumer ISPs (as a hypothesis)
- Identify notable outliers or uncommon infrastructure combinations
- Support analyst decision-making with narrative summaries and investigative leads


**Prompt:**
```
We are experiencing an application-layer (Layer 7) DDoS attack targeting an
e-commerce checkout endpoint. The attached JSONL file contains the top 500 source IPs observed over the past
hour. Each record includes IP address, ASN, ASN name, ASN domain, country, and continent.

Analyze the data and provide:
1. Geographic distribution by country and continent. Is activity broadly
   distributed or concentrated in specific regions?
2. ASN analysis: which ASNs and organizations account for the largest share of
   activity?
3. Infrastructure characteristics: based on ASN names and domains, does the
   activity appear more consistent with hosting providers or consumer ISPs?
   Clearly state assumptions and confidence. Note: Some IPs may have null ASN data - analyze these separately.
4. Identify unusual or rare ASNs, countries, or ASN/country combinations that
   may warrant further investigation.
5. Based on the observed distribution, suggest mitigation options appropriate
   for the infrastructure profile (e.g., ASN-based controls, rate limiting,
   WAF tuning), noting any limitations of this analysis.

For each mitigation, indicate feasibility (Easy/Medium/Hard) and expected effectiveness (High/Medium/Low).

Attack context:
- Target: E-commerce checkout
- Attack vector: HTTP POST flood
- Peak observed rate: ~50,000 requests/second
- Attack start time: ~45 minutes ago
```


**Expected Outcome:**

- Clear summary of geographic distribution (global vs region-heavy)
- Ranked list of top ASNs and organizations driving request volume
- Infrastructure profile hypothesis (hosting-heavy vs ISP-heavy), with stated assumptions and confidence
- Identification of outliers or atypical infrastructure patterns
- Conditional mitigation recommendations tied to observed infrastructure
- Analyst-ready narrative suitable for incident response notes

*Note: If your dataset is larger, consider filtering to top 500-1000 most active IPs*

---

### Workflow 2: Threat Feed Enrichment

*Scenario: Enrich third-party threat feeds with geographic and ASN context to improve analyst understanding and prioritization.*

**Prompt:**
```
Threat Feed Enrichment Analysis

Two datasets are provided:

Dataset A contains IP indicators from a commercial threat feed, including
threat type and confidence level.

Dataset B contains IP geolocation and ASN information from IPInfoLite.

Each dataset is attached as a separate JSONL file. The 'IP' field is the common key for correlation.

Correlate the datasets by IP address and provide:

1. Countries and ASNs with the highest concentration of threat indicators.
2. Whether specific threat types are more commonly associated with particular
   regions or network operators.
3. Differences in infrastructure characteristics between high- and
   low-confidence indicators.
4. ASNs that may warrant prioritization for review or mitigation based on
   frequency and confidence levels.
5. Any notable patterns or correlations not explicitly labeled in the threat
   feed that could inform further investigation.

Goal: Enhance threat feed value, support analyst prioritization, and reduce false positives.
```

**Expected Outcome:**
- Correlated view of threat indicators with geographic and ASN context
- Identification of infrastructure patterns associated with higher-confidence threats
- Prioritized ASNs or regions for analyst review (not automated blocking)
- Identification of potential false positives or low-signal indicators
- Analyst-ready narrative to support threat hunting and IR workflows


---

### Workflow 3: Geofencing Validation

*Scenario: Assess access logs to support validation of geo-blocking controls against policy-defined restricted countries.*


**Prompt:**
```
Compliance Review: Geofencing Controls

Policy-defined restricted countries:
Iran, North Korea, Syria, Cuba, Russia

The attached dataset contains 30 days of access logs enriched with
IP geolocation and ASN data.

Analyze the data and provide:
1. Whether IPs geolocated to restricted countries appear in the logs.
2. If present, list affected countries, IP counts, and request volume.
3. Whether the observed access patterns suggest potential gaps or
   exceptions in geofencing enforcement.
4. Identify infrastructure (e.g., hosting providers or known proxy-style
   ASNs) that may affect geolocation accuracy.
5. Generate an audit-ready summary describing observed findings,
   limitations, and areas requiring further validation.

Regulatory context:
OFAC sanctions compliance (evidence support only; not legal advice).

```

**Expected Outcome:**
- Evidence to support geofencing compliance review
- Identification of potential policy exceptions or enforcement gaps
- Contextual analysis of infrastructure affecting geolocation accuracy
- Audit-ready documentation summarizing findings and limitations

*Note: If your dataset is larger, consider filtering to top 500-1000 most active IPs*


## Contributing Use Cases

**Have a use case not covered here?**

We welcome community contributions. To propose a new use case, please provide a brief scenario description, an example prompt, and the expected outcome. Submissions can be sent to ryan.terp@gmail.com

---

**Last Updated:** January 2026  
**Module Version:** 3.0.1
