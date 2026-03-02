import os
import logging
from typing import List, Dict, Any
from apify_client import ApifyClient
from apify_client._errors import ApifyApiError

logger = logging.getLogger(__name__)    

APIFY_TOKEN = os.getenv("APIFY_TOKEN")
ACTOR_ID = "apify/instagram-profile-scraper"

if not APIFY_TOKEN:
    raise RuntimeError("APIFY_TOKEN not set in environment variables")


class InstagramProfileService:
    def __init__(self):
        self.client = ApifyClient(APIFY_TOKEN)

    def fetch_profiles(
        self,
        usernames: List[str],
        include_about: bool = False,
        timeout_secs: int = 180
    ) -> List[Dict[str, Any]]:
        """
        Runs Apify Instagram profile searcher and returns parsed results.
        """

        run_input = {
            "includeAboutSection": include_about,
            "usernames": usernames,
        }

        try:
            run = self.client.actor(ACTOR_ID).call(
                run_input=run_input,
                timeout_secs=timeout_secs
            )

            dataset_id = run["defaultDatasetId"]

            results = list(
                self.client.dataset(dataset_id).iterate_items()
            )

            return results

        except ApifyApiError as e:
            logger.error(f"Apify API error: {e}")
            raise

        except Exception as e:
            logger.exception("Unexpected error while fetching Instagram profiles")
            raise

service = InstagramProfileService()

def get_profiles(usernames: list[str]):
    try:
        results = service.fetch_profiles(usernames)
        return {"success": True, "data": results}
    except Exception:
        return ("Instagram lookup failed")

print(get_profiles(["hanavmodasiya"]))