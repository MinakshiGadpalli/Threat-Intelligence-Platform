def is_duplicate(collection, ip):
    return collection.find_one({"ip": ip}) is not None