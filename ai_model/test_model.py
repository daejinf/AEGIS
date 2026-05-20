import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from imblearn.over_sampling import SMOTE # 💡 데이터 불균형 해결사

# 1. 병합된 데이터 불러오기
file_path = r"C:\Users\kjs64\OneDrive\바탕 화면\AEGIS\data\all_features.csv"
df = pd.read_csv(file_path)

print(f"[*] 데이터 로드 완료: 총 {len(df)}개의 데이터")

# 2. 문제(X)와 정답(y) 분리 (timestamp는 학습에 방해되니 제외)
X = df.drop(columns=['timestamp', 'label'])
y = df['label']

# 3. 학습용 / 테스트용 데이터 쪼개기 (8:2 비율)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# 4. SMOTE 적용: 데이터 개수만 늘리기
smote = SMOTE(random_state=42, k_neighbors=2)
X_train_smote, y_train_smote = smote.fit_resample(X_train, y_train)

print(f"[*] SMOTE 적용 전 훈련 데이터 수: {len(X_train)}")
print(f"[*] SMOTE 적용 후 훈련 데이터 수: {len(X_train_smote)} (가장 많은 라벨 기준으로 갯수 뻥튀기 완료!)\n")

# =====================================================================
# 🚨 아까 여기서부터 밑부분이 잘려나갔습니다! 아래 코드가 꼭 있어야 합니다.
# =====================================================================

# 5. AI 모델 훈련 (class_weight='balanced'로 한 번 더 균형 잡아줌)
rf_model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
rf_model.fit(X_train_smote, y_train_smote)

# 6. 테스트 및 채점 (테스트 시에도 원본 X_test 사용)
y_pred = rf_model.predict(X_test)
acc = accuracy_score(y_test, y_pred)

print("=========================================")
print(f"✅ AI 모델 학습 완료! (정확도: {acc * 100:.2f}%)")
print("=========================================\n")
print("[상세 성적표]")
print(classification_report(y_test, y_pred))