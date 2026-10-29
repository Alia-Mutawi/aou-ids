from taipy.gui import Gui, notify
import pandas as pd
import numpy as np
import joblib

# 1. تحميل النموذج والملفات الأساسية
model = joblib.load('xgb_lightweight_final.pkl')
scaler = joblib.load('light_scaler.pkl')
features = joblib.load('top10_features.pkl')
encoder = joblib.load('label_encoder.pkl')

# 2. تهيئة المتغيرات (State Variables)
file_path = None
data_table = pd.DataFrame(columns=features) # جدول فارغ مبدئياً
total_flows = 0
num_benign = 0
num_attacks = 0
status_message = "Waiting for data..."

# 3. دالة التحليل التي تعمل عند رفع الملف
def analyze_csv(state):
    if state.file_path:
        notify(state, 'info', "Analyzing network flows...")
        
        # قراءة البيانات
        df = pd.read_csv(state.file_path)
        
        try:
            # التحقق من الخصائص وتطبيق النموذج
            data_top = df[features]
            scaled_data = scaler.transform(data_top)
            preds = model.predict(scaled_data)
            
            # حفظ النتائج
            df['Predicted_Label'] = encoder.inverse_transform(preds)
            state.data_table = df
            
            # حساب الإحصائيات للوحة التحكم
            state.total_flows = len(df)
            attacks_df = df[df['Predicted_Label'] != 'BENIGN']
            state.num_attacks = len(attacks_df)
            state.num_benign = state.total_flows - state.num_attacks
            
            # تحديث حالة النظام
            if state.num_attacks > 0:
                state.status_message = f"🚨 WARNING: {state.num_attacks} malicious flows detected!"
                notify(state, 'error', "Threats Detected!")
            else:
                state.status_message = "✅ System Secure. All flows are clean."
                notify(state, 'success', "System Secure")
                
        except Exception as e:
            notify(state, 'error', f"Missing features in CSV: {e}")

# 4. تصميم واجهة المستخدم (Taipy Markdown)
page = """
<|text-center|
# 🛡️ IoT Intrusion Detection System
**Advanced Network Flow Analysis Dashboard**
|>

---

### 📁 Upload Network Traffic Data (CSV)
<|{file_path}|file_selector|label=Select CSV File|extensions=.csv|on_action=analyze_csv|>

<br/>

<|layout|columns=1 1 1|
<|card|
### Total Flows
## <|{total_flows}|>
|>

<|card|
### Safe (BENIGN)
## <|{num_benign}|>
|>

<|card|
### Detected Attacks
## <|{num_attacks}|>
|>
|>

<br/>
<|{status_message}|text|class_name=h3|>

---

### 📊 Detailed Flow Analysis
<|{data_table}|table|page_size=10|rebuild|>
"""

if __name__ == "__main__":
    # تشغيل التطبيق (مع السماح للمنصات السحابية بالوصول)
    Gui(page=page).run(title="IoT IDS Dashboard", host="0.0.0.0", port=7860, dark_mode=True, use_reloader=False)
