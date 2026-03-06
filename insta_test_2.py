import os
import logging
from typing import List, Dict, Any
from apify_client import ApifyClient
from apify_client._errors import ApifyApiError




def fetch_profiles_insta(
    usernames: List[str],
    include_about: bool = False,
    timeout_secs: int = 30
) -> List[Dict[str, Any]]:
    """
    Runs Apify Instagram profile searcher and returns parsed results.
    """

    # print(os.getenv("APIFY_API"))
    client = ApifyClient(os.getenv("APIFY_API"))
    INSTA_ACTOR_ID = "apify/instagram-profile-scraper"
    run_input = {
        "includeAboutSection": include_about,
        "usernames": usernames,
    }

    try:
        run = client.actor(INSTA_ACTOR_ID).call(
            run_input=run_input,
            timeout_secs=timeout_secs
        )

        dataset_id = run["defaultDatasetId"]

        results = list(
            client.dataset(dataset_id).iterate_items()
        )

        return results

    except ApifyApiError as e:
        return f"Apify API error: {e}"

    except Exception as e:
        return "Unexpected error while fetchinjg profiles"



logger = logging.getLogger(__name__)


def get_profiles(usernames: list[str]):
    try:
        results = fetch_profiles_insta(usernames)
        return {"success": True, "data": results}
    except Exception:
        return ("Instagram lookup failed")

d = get_profiles(["hanavmodasiya"])
# print(d)  
if (d["success"] == False):
    print("Username doesnt exist")
else:
    print(d["data"][0]["username"])
    print(d["data"][0]["fullName"])
    print(d["data"][0]["profilePicUrlHD"])