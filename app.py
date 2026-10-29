import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os

st.set_page_config(page_title="IoT IDS Dashboard", layout="wide")

st.title("🛡️ نظام كشف التسلل (IDS) لشبكات إنترنت الأشياء")
st.markdown("لوحة تحكم تفاعلية لمراقبة تدفقات الشبكة واكتشاف هجمات **Botnet** و **Slowloris** باستخدام النموذج الخفيف المطور.")



@st.cache_resource
def load_artifacts():
    # تحميل الملفات من المجلد الصحيح
    model = joblib.load(os.path.join(ARTIFACT_DIR, 'xgb_lightweight_final.pkl'))
    scaler = joblib.load(os.path.join(ARTIFACT_DIR, 'light_scaler.pkl'))
    features = joblib.load(os.path.join(ARTIFACT_DIR, 'top10_features.pkl'))
    encoder = joblib.load(os.path.join(ARTIFACT_DIR, 'label_encoder.pkl'))
    return model, scaler, features, encoder

try:
    model, scaler, features, encoder = load_artifacts()
    st.sidebar.success("✅ تم تحميل النموذج والملفات بنجاح!")
except Exception as e:
    st.sidebar.error(f"⚠️ خطأ في تحميل الملفات: {e}")

tab1, tab2 = st.tabs(["📝 إدخال يدوي لتدفق واحد", "📁 رفع ملف تدفقات CSV"])

with tab1:
    st.header("إدخال خصائص التدفق (Top 10 Features)")
    user_inputs = []
    
    # تقسيم الحقول إلى أعمدة لتصبح الواجهة مرتبة
    cols = st.columns(2)
    for i, feat in enumerate(features):
        with cols[i % 2]:
            val = st.number_input(f"{feat}", value=0.0, format="%.4f")
            user_inputs.append(val)
        
    if st.button("🔍 فحص حركة المرور (Analyze Flow)"):
        input_array = np.array([user_inputs])
        scaled_input = scaler.transform(input_array)
        
        prediction_num = model.predict(scaled_input)[0]
        prediction_label = encoder.inverse_transform([prediction_num])[0]
        
        st.divider()
        if prediction_label == 'BENIGN':
            st.success("✅ **حركة المرور طبيعية (BENIGN).** لا يوجد تهديد حالي.")
        elif prediction_label == 'Bot':
            st.error("🚨 **تحذير حرج: تم اكتشاف هجوم من نوع Botnet!**")
            st.warning("الإجراء المقترح: عزل العقدة المصابة في شبكة IoT فوراً.")
        elif prediction_label == 'DoS_Slowloris':
            st.error("🚨 **تحذير حرج: تم اكتشاف هجوم من نوع DoS_Slowloris!**")
            st.warning("الإجراء المقترح: تفعيل حماية خادم الويب وتقليل مهلة الاتصال.")

with tab2:
    st.header("تحليل ملف تدفقات شبكية")
    uploaded_file = st.file_uploader("قم برفع ملف CSV يحتوي على الخصائص", type=["csv"])
    if uploaded_file is not None:
        data = pd.read_csv(uploaded_file)
        st.write("معاينة البيانات المرفوعة:", data.head())
        
        if st.button("📊 تحليل الملف كامل"):
            try:
                data_top = data[features]
                scaled_data = scaler.transform(data_top)
                
                preds_num = model.predict(scaled_data)
                data['Predicted_Label'] = encoder.inverse_transform(preds_num)
                
                st.success("تم تحليل الملف بنجاح!")
                st.dataframe(data)
                
                csv_result = data.to_csv(index=False).encode('utf-8')
                st.download_button("📥 تنزيل تقرير التحليل (CSV)", data=csv_result, file_name="ids_analysis_report.csv", mime="text/csv")
            except Exception as e:
                st.error(f"تأكد من أن الملف يحتوي على الخصائص المطلوبة: {e}")
