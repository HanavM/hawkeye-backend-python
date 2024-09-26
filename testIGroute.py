from instagram import Instagram
import json

try:
    profile_data = Instagram.scrap('varundangeti')
    profile_data = json.loads(profile_data)
    # print(profile_data)
    full_name = profile_data["full_name"]
    if full_name:
        name_parts = full_name.split(" ")
        first_name = name_parts[0]
        last_name = name_parts[1] if len(name_parts) > 1 else ""
    print(first_name + " xxx " + last_name)
except:
    print("well account doesnt exist")
# print(profile_data)
# print(profile_data)
# print(profile_data["full_name"])
print("no error yet")