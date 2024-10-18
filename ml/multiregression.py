import pandas
from sklearn import linear_model

df = pandas.read_csv("data.csv")

X = df[['cyclomatic','loops','nestDegree','sloc','aloc','localVars','localPtrVars','ptrArgs','isReturningPtrs','callees','callers','height','conditions','cmps','jmps']]

# y = df['vuln']
y = df['codeComplexity']

regr = linear_model.LinearRegression()
regr.fit(X, y)

print(regr.coef_)