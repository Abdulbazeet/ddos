import joblib

scaler = joblib.load("model/scaler.pkl")

print(scaler.feature_names_in_)