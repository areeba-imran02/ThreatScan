
import os
import streamlit as st
from groq import Groq
from sources import SOURCES


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="ThreatScan",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)


# =========================================================
# SESSION STATE
# =========================================================

defaults = {
    "scan_result": None,
    "scanned_target": "",
    "analysis_level": "Intermediate",
    "ai_analysis": None
}

for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value


# =========================================================
# PROFESSIONAL THEME
# =========================================================

st.markdown("""
<style>
.stApp {
    background:
        radial-gradient(circle at top left, #e8f0ff 0%, transparent 32%),
        radial-gradient(circle at top right, #f1e8ff 0%, transparent 30%),
        linear-gradient(135deg, #f8fbff 0%, #f5f7ff 50%, #f7fbfa 100%);
}

.block-container {
    max-width: 1180px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}

h1 {
    color: #17213b;
    font-weight: 800;
    letter-spacing: -1px;
}

h2, h3 {
    color: #202b47;
    font-weight: 750;
}

[data-testid="stHeader"] {
    background: transparent;
}

div.stButton > button {
    background: linear-gradient(135deg, #3346a8, #7055c9);
    color: white;
    border: none;
    border-radius: 12px;
    min-height: 48px;
    font-weight: 700;
    font-size: 1rem;
    box-shadow: 0 7px 18px rgba(65, 73, 170, 0.20);
}

div.stButton > button:hover {
    background: linear-gradient(135deg, #28398f, #5d45ad);
    color: white;
}

div[data-testid="stMetric"] {
    background: rgba(255,255,255,0.88);
    border: 1px solid #dfe5f2;
    border-radius: 15px;
    padding: 14px;
    box-shadow: 0 5px 16px rgba(39, 52, 88, 0.06);
}

div[data-testid="stMetricLabel"] {
    color: #59657f;
}

div[data-testid="stMetricValue"] {
    color: #18233d;
    font-weight: 800;
}

.stTextInput > div > div,
.stSelectbox > div > div {
    border-radius: 11px;
}

div[data-testid="stExpander"] {
    background: rgba(255,255,255,0.75);
    border: 1px solid #dfe5f2;
    border-radius: 14px;
}

.scan-target {
    background: linear-gradient(135deg, #eef3ff, #f5efff);
    border-left: 5px solid #5366c9;
    padding: 16px 20px;
    border-radius: 13px;
    margin: 12px 0 20px 0;
}

.scan-target-label {
    color: #69748d;
    font-size: 0.78rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.scan-target-value {
    color: #202b47;
    font-size: 1.18rem;
    font-weight: 750;
    margin-top: 5px;
    word-break: break-word;
}

.ai-box {
    background: linear-gradient(135deg, #f0ecff, #edf5ff);
    border: 1px solid #d8d8ef;
    border-radius: 17px;
    padding: 18px;
    margin-top: 10px;
}

.footer-text {
    text-align: center;
    color: #737e94;
    font-size: 0.82rem;
    margin-top: 28px;
}
</style>
""", unsafe_allow_html=True)


# =========================================================
# HERO
# =========================================================

st.title("🛡️ ThreatScan")
st.caption("Scan before you trust.")

st.write(
    "Analyze an IP address, domain, or URL using "
    "VirusTotal and WHOIS intelligence."
)

st.divider()


# =========================================================
# SCANNER
# =========================================================

st.header("🔎 Security Scanner")

target = st.text_input(
    "Target",
    placeholder="Enter an IP address, domain, or URL"
)

analysis_level = st.selectbox(
    "Analysis Level",
    ["Beginner", "Intermediate", "Advanced"],
    index=1
)

scan = st.button(
    "🔍 Scan Target",
    use_container_width=True
)


# =========================================================
# GROQ AI
# =========================================================

def generate_ai_analysis(target, results, level):

    api_key = os.getenv("GROQ_API_KEY", "").strip()

    if not api_key:
        return (
            "### AI Analysis Unavailable\n\n"
            "Groq API key is not configured."
        )

    vt = results.get("VirusTotal", {})
    whois_result = results.get("WHOIS", {})

    prompt = f"""
You are the ThreatScan cybersecurity analysis assistant.

Analyze ONLY the supplied VirusTotal and WHOIS information.

TARGET:
{target}

ANALYSIS LEVEL:
{level}

VIRUSTOTAL:
{vt}

WHOIS:
{whois_result}

STRICT RULES:
- Never invent findings.
- Never invent scores.
- Never invent reputation values.
- Never say a target is completely safe.
- A harmless majority does NOT override malicious detections.
- If malicious detections exist, clearly mention them.
- If data is unavailable, explicitly say unavailable.
- WHOIS registration information alone does not prove safety.
- Do not make claims that are not supported by the supplied data.

Write a clear security assessment using these sections:

### Risk Assessment
Give Low, Medium, High, or Unknown and explain the evidence.

### VirusTotal Interpretation
Explain the actual detection counts.

### WHOIS Interpretation
Explain the available registration information.

### Overall Assessment
Give a cautious conclusion based only on the evidence.

### Recommended Action
Give practical security advice.

Match the explanation to the selected analysis level.
"""

    try:

        client = Groq(api_key=api_key)

        response = client.chat.completions.create(
            model="openai/gpt-oss-120b",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a careful cybersecurity analyst. "
                        "Never fabricate evidence."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.2
        )

        return response.choices[0].message.content

    except Exception as error:

        return (
            "### AI Analysis Unavailable\n\n"
            f"Groq AI request failed: {error}"
        )


# =========================================================
# SCAN
# =========================================================

if scan:

    if not target.strip():

        st.warning(
            "Please enter an IP address, domain, or URL."
        )

    else:

        target = target.strip()
        results = {}

        with st.spinner(
            "Collecting security intelligence..."
        ):

            for source_name, source_function in SOURCES.items():

                try:

                    results[source_name] = source_function(
                        target
                    )

                except Exception:

                    results[source_name] = {
                        "status": "error",
                        "message": "Source unavailable."
                    }

        st.session_state.scan_result = results
        st.session_state.scanned_target = target
        st.session_state.analysis_level = analysis_level

        with st.spinner(
            "Generating AI security analysis..."
        ):

            st.session_state.ai_analysis = (
                generate_ai_analysis(
                    target,
                    results,
                    analysis_level
                )
            )


# =========================================================
# RESULTS
# =========================================================

if st.session_state.scan_result is not None:

    results = st.session_state.scan_result
    target = st.session_state.scanned_target
    analysis_level = st.session_state.analysis_level

    st.divider()
    st.header("📊 Scan Results")

    st.markdown(
        f"""
        <div class="scan-target">
            <div class="scan-target-label">Scanned Target</div>
            <div class="scan-target-value">{target}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.caption(
        f"Analysis level: {analysis_level}"
    )


    # =====================================================
    # SOURCES
    # =====================================================

    st.subheader("🧠 Intelligence Sources")

    source_columns = st.columns(len(SOURCES))

    for column, source_name in zip(
        source_columns,
        SOURCES.keys()
    ):

        source_data = results.get(
            source_name,
            {}
        )

        with column:

            if source_data.get("status") == "success":

                st.success(
                    f"✓ {source_name}\n\nData available"
                )

            else:

                st.warning(
                    f"⚠ {source_name}\n\nData unavailable"
                )


    # =====================================================
    # VIRUSTOTAL
    # =====================================================

    vt = results.get("VirusTotal")

    if vt:

        st.subheader("🦠 VirusTotal Findings")

        if vt.get("status") == "success":

            stats = vt.get("stats", {})

            c1, c2, c3, c4 = st.columns(4)

            with c1:
                st.metric(
                    "Malicious",
                    stats.get("malicious", 0)
                )

            with c2:
                st.metric(
                    "Suspicious",
                    stats.get("suspicious", 0)
                )

            with c3:
                st.metric(
                    "Harmless",
                    stats.get("harmless", 0)
                )

            with c4:
                st.metric(
                    "Undetected",
                    stats.get("undetected", 0)
                )

        else:

            st.info(
                vt.get(
                    "message",
                    "VirusTotal data unavailable."
                )
            )


    # =====================================================
    # WHOIS
    # =====================================================

    whois_result = results.get("WHOIS")

    if whois_result:

        st.subheader("🌐 WHOIS Information")

        if whois_result.get("status") == "success":

            data = whois_result.get("data", {})

            c1, c2 = st.columns(2)

            with c1:

                st.write("**Domain Name**")
                st.write(
                    data.get(
                        "domain_name",
                        "Not available"
                    )
                )

                st.write("**Registrar**")
                st.write(
                    data.get(
                        "registrar",
                        "Not available"
                    )
                )

                st.write("**Creation Date**")
                st.write(
                    data.get(
                        "creation_date",
                        "Not available"
                    )
                )

            with c2:

                st.write("**Expiration Date**")
                st.write(
                    data.get(
                        "expiration_date",
                        "Not available"
                    )
                )

                st.write("**Name Servers**")
                st.write(
                    data.get(
                        "name_servers",
                        "Not available"
                    )
                )

        else:

            st.info(
                whois_result.get(
                    "message",
                    "WHOIS information unavailable."
                )
            )


    # =====================================================
    # AI ANALYSIS
    # =====================================================

    st.subheader("🤖 AI Security Analysis")

    st.caption(
        f"Groq AI • {analysis_level} analysis"
    )

    if st.session_state.ai_analysis:

        st.markdown(
            st.session_state.ai_analysis
        )

    else:

        st.info(
            "AI analysis is unavailable."
        )


# =========================================================
# FOOTER
# =========================================================

st.divider()

st.caption(
    "ThreatScan • Transparent security intelligence • "
    "VirusTotal + WHOIS • No fabricated scan results"
)
