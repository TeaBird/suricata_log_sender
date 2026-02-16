import os
import sys
import time
import logging
import requests
from typing import Optional

# ===============================
# CONFIG
# ===============================

BASE_URL = os.getenv("IDECO_URL")
USERNAME = os.getenv("IDECO_USER")
PASSWORD = os.getenv("IDECO_PASS")

LOGIN_URL = f"{BASE_URL}/auth/login"
EVENTS_URL = f"{BASE_URL}/api/events"

REQUEST_TIMEOUT = 30
RELOGIN_RETRIES = 2


# ===============================
# LOGGING
# ===============================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

logger = logging.getLogger("ideco-client")


# ===============================
# CLIENT
# ===============================

class IdecoClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = True  # False только если самоподписанный cert
        self.logged_in = False

    def login(self) -> bool:
        """
        Авторизация в IDECO 21.11
        """
        try:
            logger.info("Getting login page (CSRF/cookies)...")
            self.session.get(LOGIN_URL, timeout=REQUEST_TIMEOUT)

            payload = {
                "username": USERNAME,
                "password": PASSWORD,
            }

            logger.info("Sending login request...")
            response = self.session.post(
                LOGIN_URL,
                data=payload,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True
            )

            if response.status_code not in (200, 302):
                logger.error(f"Login failed: {response.status_code}")
                return False

            # Проверяем cookie
            cookies = self.session.cookies.get_dict()
            if not cookies:
                logger.error("Login failed: no cookies received")
                return False

            logger.info("Login successful")
            self.logged_in = True
            return True

        except Exception as e:
            logger.exception(f"Login error: {e}")
            return False

    def _request_with_relogin(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Делает запрос с авто-релогином
        """
        for attempt in range(RELOGIN_RETRIES + 1):
            response = self.session.request(
                method,
                url,
                timeout=REQUEST_TIMEOUT,
                **kwargs
            )

            if response.status_code in (401, 403):
                logger.warning("Session expired. Re-login required.")
                if not self.login():
                    logger.error("Re-login failed.")
                    return None
                continue

            return response

        logger.error("Max relogin attempts exceeded.")
        return None

    def get_events(self, date_from: str, date_to: str):
        params = {
            "date_from": date_from,
            "date_to": date_to,
        }

        response = self._request_with_relogin("GET", EVENTS_URL, params=params)

        if not response:
            return None

        if response.status_code != 200:
            logger.error(f"Failed to get events: {response.status_code}")
            return None

        try:
            return response.json()
        except Exception:
            logger.error("Invalid JSON response")
            return None


# ===============================
# MAIN
# ===============================

def main():
    if not BASE_URL or not USERNAME or not PASSWORD:
        logger.error("Environment variables not set.")
        sys.exit(1)

    client = IdecoClient()

    if not client.login():
        logger.error("Initial login failed.")
        sys.exit(1)

    # пример запроса
    events = client.get_events(
        date_from="2026-02-15 00:00:00",
        date_to="2026-02-16 00:00:00"
    )

    if events:
        logger.info(f"Received {len(events)} events")
    else:
        logger.error("No events received")


if __name__ == "__main__":
    main()
