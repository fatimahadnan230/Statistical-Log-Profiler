[# Statistical-Log-Profiler](https://statistical-log-profiler-4z4umrtzg9zymflqz59vuh.streamlit.app/)
# 🛡️ Statistical Log Parser & Traffic Profiler

An interactive security analytics dashboard built in Python that parses raw, unstructured web server traffic logs and isolates high-risk structural anomalies (potential Data Exfiltration, DDoS, or vulnerability scanning) using standard deviation ($\sigma$) calculations.

## 🚀 Core Features
* **Python Regex Engine:** Cleans and tokenizes raw Nginx/Apache log strings into structured dataframes.
* **Pandas Feature Profiling:** Groups traffic by unique IP nodes to compute active transmission counts and average payload distributions.
* **NumPy Anomaly Detection:** Applies Z-score thresholding ($>2\sigma$) to isolate statistical outliers without relying on heavy machine learning models.
* **Interactive UI:** A lightweight web dashboard featuring responsive threshold tuners, Plotly scatter clusters, and risk registries.

## 🛠️ Tech Stack
* **Language:** Python 3
* **Libraries:** Pandas, NumPy, Plotly
* **Framework:** Streamlit

## 📦 Installation & Setup
1. Clone the repository:
   ```bash
   git clone [https://github.com/YOUR_USERNAME/Statistical-Log-Profiler.git](https://github.com/YOUR_USERNAME/Statistical-Log-Profiler.git)
