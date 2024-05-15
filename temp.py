import pickle

data = {}

with open("data.pkl", 'wb') as file:
    pickle.dump(data, file)