from instagram import Instagram
import json

while (True):
    username = input("Enter Instagram username: ")
    if (username == "x"): 
        break
    try:
        profile_data = Instagram.scrap(username)
        profile_data = json.loads(profile_data)
        # print(profile_data)
        full_name = profile_data["full_name"]
        print("full_name: '", full_name,"'")
        first_name = ""
        last_name = ""

        if full_name:
            name_parts = full_name.split(" ")
            first_name = name_parts[0]
            last_name = name_parts[1] if len(name_parts) > 1 else ""
        print(first_name + " xxx " + last_name)
        print("im right herererer")
    except Exception as e:
        print(f"well account doesnt exist {e}")
# print(profile_data)
# print(profile_data)
# print(profile_data["full_name"])
print("no error yet")