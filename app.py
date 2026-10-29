import streamlit as st
import pandas as pd
import numpy as np
import joblib

st.set_page_config(page_title="IoT IDS Dashboard", layout="wide")

st.title("🛡️ IoT Intrusion Detection System (IDS)")
st.markdown("Interactive dashboard for monitoring network flows and detecting **Botnet** and **Slowloris** attacks using the optimized lightweight model.")

@st.cache_resource
def load_artifacts():
    model = joblib.load('xgb_lightweight_final.pkl')
    imputer = joblib.load('light_imputer.pkl')  # إضافة الـ imputer المفقود
    scaler = joblib.load('light_scaler.pkl')
    features = joblib.load('top10_features.pkl')
    encoder = joblib.load('label_encoder.pkl')
    return model, imputer, scaler, features, encoder

try:
    model, imputer, scaler, features, encoder = load_artifacts()
    st.sidebar.success("✅ Model and artifacts loaded successfully!")
except Exception as e:
    st.sidebar.error(f"⚠️ Error loading artifacts: {e}")

tab1, tab2 = st.tabs(["📝 Single Flow Manual Input", "📁 Batch CSV File Analysis"])

with tab1:
    st.header("Enter Top 10 Flow Features")
    user_inputs = []
    
    cols = st.columns(2)
    for i, feat in enumerate(features):
        with cols[i % 2]:
            val = st.number_input(f"{feat}", value=0.0, format="%.4f")
            user_inputs.append(val)
        
    if st.button("🔍 Analyze Network Flow"):
        input_array = np.array([user_inputs])
        imputed_input = imputer.transform(input_array) # معالجة القيم المفقودة
        scaled_input = scaler.transform(imputed_input)
        
        prediction_num = model.predict(scaled_input)[0]
        prediction_label = encoder.inverse_transform([prediction_num])[0]
        
        st.divider()
        if prediction_label == 'BENIGN':
            st.success("✅ **Traffic is BENIGN.** No current threats detected.")
        elif prediction_label == 'Bot':
            st.error("🚨 **CRITICAL ALERT: Botnet Attack Detected!**")
            st.warning("Recommended Action: Isolate the affected IoT node from the network immediately.")
        elif prediction_label == 'DoS_Slowloris':
            st.error("🚨 **CRITICAL ALERT: DoS Slowloris Attack Detected!**")
            st.warning("Recommended Action: Enable web server protection and decrease connection timeout limits.")

with tab2:
    st.header("Batch Network Flow Analysis & Security Alerts")
    uploaded_file = st.file_uploader("Upload a CSV file containing flow features", type=["csv"])
    if uploaded_file is not None:
        data = pd.read_csv(uploaded_file)
        st.write("Uploaded Data Preview:", data.head())
        
        if st.button("📊 Run Security Analysis"):
            try:
                data_top = data[features]
                imputed_data = imputer.transform(data_top) # المعالجة الصحيحة للدفعة
                scaled_data = scaler.transform(imputed_data)
                
                preds_num = model.predict(scaled_data)
                data['Predicted_Label'] = encoder.inverse_transform(preds_num)
                
                # حساب إحصائيات التهديدات
                total_flows = len(data)
                attacks = data[data['Predicted_Label'] != 'BENIGN']
                num_attacks = len(attacks)
                num_benign = total_flows - num_attacks
                
                bot_count = len(data[data['Predicted_Label'] == 'Bot'])
                slow_count = len(data[data['Predicted_Label'] == 'DoS_Slowloris'])
                
                st.divider()
                st.subheader("🚨 Security Incident Summary")
                
                col1, col2, col3 = st.columns(3)
                col1.metric("Total Flows Analyzed", total_flows)
                col2.metric("Benign Traffic", num_benign, delta="Safe")
                col3.metric("Detected Attacks", num_attacks, delta=f"-{num_attacks} Threats" if num_attacks > 0 else "Secure", delta_color="inverse")
                
                if num_attacks > 0:
                    st.error(f"⚠️ **WARNING: {num_attacks} malicious network flows detected!**")
                    if bot_count > 0:
                        st.warning(f"🔴 **Botnet Flows:** {bot_count} flows identified. Immediate node isolation recommended.")
                    if slow_count > 0:
                        st.warning(f"🟠 **DoS Slowloris Flows:** {slow_count} flows identified. Check web server timeouts.")
                else:
                    st.success("✅ **All network flows are clean and secure!**")
                
                st.subheader("Detailed Analysis Results")
                st.dataframe(data)
                
                csv_result = data.to_csv(index=False).encode('utf-8')
                st.download_button("📥 Download Security Report (CSV)", data=csv_result, file_name="ids_security_report.csv", mime="text/csv")
            except Exception as e:
                st.error(f"Please ensure the CSV file contains the required features: {e}")
