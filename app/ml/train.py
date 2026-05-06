
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

def train_model():
    print("Loading dataset...")

    df1 = pd.read_csv("data/F.csv")
    df2 = pd.read_csv("data/J.csv")
    df3 = pd.read_csv("data/M.csv")
    df4 = pd.read_csv("data/w.csv")

    df = pd.concat([df1, df2, df3, df4], ignore_index=True)

    print("Dataset loaded:", df.shape)

    # Keep only numeric columns
    df = df.select_dtypes(include=['int64', 'float64'])

    # 🔥 FIX 1: Replace infinity with NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # 🔥 FIX 2: Drop rows with NaN
    df.dropna(inplace=True)

    print("After cleaning:", df.shape)

    # Split features and labels
    X = df.iloc[:, :-1]
    y = df.iloc[:, -1]

    # 🔥 FIX 3: Reduce dataset size (important for speed)
    X = X.sample(n=50000, random_state=42)
    y = y.loc[X.index]

    print("Training on reduced dataset:", X.shape)

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2
    )

    model = RandomForestClassifier(
    n_estimators=10,
    max_depth=10,
    random_state=42
)

    model.fit(X_train, y_train)

    joblib.dump(model, "app/ml/model.pkl")

    print("✅ Model trained and saved successfully!")