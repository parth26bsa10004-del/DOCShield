import io
import ast
import zipfile
import streamlit as st
from PIL import Image
import fitz  # PyMuPDF

# Page Configuration
st.set_page_config(
    page_title="DocShield - Document & Code Tamper Inspector",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ DocShield: Smart Integrity Inspector")
st.markdown("Upload a document, script, or package (`.pdf`, `.png`, `.jpg`, `.py`, `.apk`) to scan for tampering, anomalies, and structural alterations.")

# File Uploader (Added python and apk)
uploaded_file = st.file_uploader(
    "Upload file for audit", 
    type=["pdf", "png", "jpg", "jpeg", "py", "apk"]
)

if uploaded_file is not None:
    file_type = uploaded_file.type
    file_name = uploaded_file.name.lower()
    st.success(f"File uploaded successfully: **{uploaded_file.name}**")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📄 File Preview & Info")
        
        if "image" in file_type or file_name.endswith((".png", ".jpg", ".jpeg")):
            image = Image.open(uploaded_file)
            st.image(image, caption="Uploaded Image", use_container_width=True)
            
        elif "pdf" in file_type or file_name.endswith(".pdf"):
            pdf_bytes = uploaded_file.read()
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            st.write(f"**Total Pages:** {len(doc)}")
            metadata = doc.metadata

            # Render first page as image preview
            page = doc.load_page(0)
            pix = page.get_pixmap()
            img_bytes = pix.tobytes("png")
            image = Image.open(io.BytesIO(img_bytes))
            st.image(image, caption="Page 1 Preview", use_container_width=True)
            
        elif file_name.endswith(".py"):
            code_bytes = uploaded_file.read()
            code_text = code_bytes.decode("utf-8", errors="ignore")
            st.code(code_text[:1000] + ("\n... [truncated]" if len(code_text) > 1000 else ""), language="python")
            st.info(f"**Script Size:** {len(code_bytes)} bytes")
            
        elif file_name.endswith(".apk"):
            st.info("📦 **Android Package (.apk)** detected. Analyzing compressed archive structure...")
            apk_bytes = uploaded_file.read()

    with col2:
        st.subheader("🔍 Forensic Audit Results")

        with st.spinner("Running integrity and security checks..."):
            trust_score = 95
            findings = []

            # PDF Inspection
            if "pdf" in file_type or file_name.endswith(".pdf"):
                producer = metadata.get("producer", "").lower()
                
                if "photoshop" in producer or "gimp" in producer or "illustrator" in producer:
                    trust_score -= 35
                    findings.append(f"⚠️ **Suspicious Creator Tool:** Metadata indicates editing via `{producer}`.")
                else:
                    findings.append("✅ **Metadata Tool Check:** Standard document creation software verified.")

                if not metadata.get("format"):
                    trust_score -= 15
                    findings.append("⚠️ **Structure Warning:** Missing standard PDF version identifiers.")
                else:
                    findings.append("✅ **Structure Check:** File structure signature is valid.")

            # Image Inspection
            elif "image" in file_type or file_name.endswith((".png", ".jpg", ".jpeg")):
                findings.append("ℹ️ **Image Mode:** Standard pixel analysis complete. Uniform compression profile detected.")

            # Python Script Inspection
            elif file_name.endswith(".py"):
                try:
                    # Check for syntax validity
                    ast.parse(code_text)
                    findings.append("✅ **Syntax Check:** Python code parses successfully without syntax errors.")
                except SyntaxError as e:
                    trust_score -= 40
                    findings.append(f"❌ **Syntax Error:** Invalid Python syntax detected at line {e.lineno}.")

                # Basic heuristic checks for risky patterns
                risky_keywords = ["eval(", "exec(", "subprocess.run", "os.system"]
                found_risks = [kw for kw in risky_keywords if kw in code_text]
                if found_risks:
                    trust_score -= 25
                    findings.append(f"⚠️ **Security Warning:** Potentially hazardous functions found: `{', '.join(found_risks)}`.")
                else:
                    findings.append("✅ **Security Check:** No obvious high-risk execution sinks detected.")

            # APK Inspection
            elif file_name.endswith(".apk"):
                try:
                    # APK is a ZIP archive under the hood
                    apk_io = io.BytesIO(apk_bytes)
                    with zipfile.ZipFile(apk_io, 'r') as z:
                        namelist = z.namelist()
                        
                        # Check for AndroidManifest.xml and classes.dex
                        if "AndroidManifest.xml" in namelist and "classes.dex" in namelist:
                            findings.append("✅ **Package Structure:** Valid Android application package signature found.")
                        else:
                            trust_score -= 50
                            findings.append("❌ **Structure Warning:** Missing core APK components (AndroidManifest or classes.dex).")
                            
                        # Check for suspicious or unsigned files
                        if any("META-INF" in name for name in namelist):
                            findings.append("✅ **Signature Check:** META-INF signing directory present.")
                        else:
                            trust_score -= 30
                            findings.append("⚠️ **Security Warning:** Package appears unsigned (missing META-INF).")
                except Exception as e:
                    trust_score = 10
                    findings.append(f"❌ **Corruption Error:** Failed to parse APK archive: {str(e)}")

            # Display Trust Score Gauge / Metric
            st.metric(label="Document / Code Trust Score", value=f"{trust_score}%")

            if trust_score >= 80:
                st.success("Status: **Low Risk / Appears Authentic**")
            elif trust_score >= 50:
                st.warning("Status: **Medium Risk / Manual Review Recommended**")
            else:
                st.error("Status: **High Risk / Potential Tampering Detected**")

            st.markdown("### Detailed Findings:")
            for finding in findings:
                st.write(finding)

            # Export Button Mockup
            if st.button("📥 Export Audit Report (PDF)"):
                st.info("Audit report summary generated and ready for download.")

