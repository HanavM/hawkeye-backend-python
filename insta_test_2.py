import os
import logging
from typing import List, Dict, Any
from apify_client import ApifyClient
from apify_client._errors import ApifyApiError


client = ApifyClient(os.getenv("APIFY_API"))
INSTA_ACTOR_ID = "apify/instagram-profile-scraper"

def fetch_profiles_insta(
    usernames: List[str],
    include_about: bool = False,
    timeout_secs: int = 30
) -> List[Dict[str, Any]]:
    """
    Runs Apify Instagram profile searcher and returns parsed results.
    """

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

APIFY_TOKEN = os.getenv("APIFY_TOKEN")
ACTOR_ID = "YOUR_USERNAME/instagram-profile-searcher"

if not APIFY_TOKEN:
    raise RuntimeError("APIFY_TOKEN not set in environment variables")


def get_profiles(usernames: list[str]):
    try:
        results = fetch_profiles_insta(usernames)
        return {"success": True, "data": results}
    except Exception:
        return ("Instagram lookup failed")

print(get_profiles(["hanavmodasiya"]))