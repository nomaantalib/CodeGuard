# Seeded flaw: mutable default list
def append_item(item, target_list=[]):
    target_list.append(item)
    return target_list
