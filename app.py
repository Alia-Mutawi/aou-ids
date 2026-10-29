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
data_table = pd.DataFrame()
total_flows = 0
num_benign = 0
num_attacks = 0
status_message = "Waiting for data..."

# 3. دالة التحليل المحدثة لتحديث حالة Taipy بوضوح
def analyze_csv(state):
    if state.file_path:
        notify(state, 'info', "Analyzing network flows...")
        
        try:
            # قراءة البيانات
            df = pd.read_csv(state.file_path)
            
            # التأكد من أخذ الخصائص بالترتيب الصحيح
            data_top = df[list(features)]
            scaled_data = scaler.transform(data_top)
            preds = model.predict(scaled_data)
            
            # تطبيق التنبؤات
            df['Predicted_Label'] = encoder.inverse_transform(preds)
            
            # حساب الإحصائيات بدقة
            t_flows = len(df)
            attacks_df = df[df['Predicted_Label'] != 'BENIGN']
            n_attacks = len(attacks_df)
            n_benign = t_flows - n_attacks
            
            # تحديث المتغيرات عبر state لتظهر في الواجهة فوراً
            state.data_table = df
            state.total_flows = t_flows
            state.num_attacks = n_attacks
            state.num_benign = n_benign
            
            if n_attacks > 0:
                state.status_message = f"🚨 WARNING: {n_attacks} malicious flows detected!"
                notify(state, 'error', f"Detected {n_attacks} threats!")
            else:
                state.status_message = "✅ System Secure. All flows are clean."
                notify(state, 'success', "System Secure")
                
        except Exception as e:
            notify(state, 'error', f"Error during analysis: {e}")

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
    Gui(page=page).run(title="IoT IDS Dashboard", host="0.0.0.0", port=7860, dark_mode=True, use_reloader=False)
