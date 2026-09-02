#
#  GoogleFindMyTools - A set of tools to interact with the Google Find My API
#  Copyright © 2024 Leon Böttger. All rights reserved.
#

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as ec

from KeyBackup.response_parser import get_fmdn_shared_key
from KeyBackup.shared_key_request import get_security_domain_request_url
from chrome_driver import create_driver

def request_shared_key_flow():
    driver = create_driver()
    try:
        # Open Google accounts sign-in page. Starting at myaccount.google.com
        # ensures the post-signin redirect lands back on myaccount.google.com,
        # which is what the WebDriverWait below matches on.
        driver.get("https://myaccount.google.com/")

        # Wait for the user to complete sign-in. Google may redirect to
        # various pages afterwards (myaccount, the account "about" page, etc.),
        # so simply wait until we leave the accounts.google.com sign-in flow.
        import time
        deadline = time.time() + 300
        signed_in = False
        while time.time() < deadline:
            url = driver.current_url
            if "accounts.google.com" not in url:
                signed_in = True
                break
            time.sleep(2)
        if not signed_in:
            raise Exception("user did not complete sign-in within 300s")
        print("[SharedKeyFlow] Signed in successfully.")

        # Open the security domain request URL
        security_url = get_security_domain_request_url()
        driver.get(security_url)

        # Inject JavaScript interface
        script = """
        window.mm = {
            setVaultSharedKeys: function(str, vaultKeys) {
                console.log('setVaultSharedKeys called with:', str, vaultKeys);
                alert(JSON.stringify({ method: 'setVaultSharedKeys', str: str, vaultKeys: vaultKeys }));
            },
            closeView: function() {
                console.log('closeView called');
                alert(JSON.stringify({ method: 'closeView' }));
            }
        };
        """
        driver.execute_script(script)

        while True:
            # Check for alerts indicating JavaScript calls
            try:
                WebDriverWait(driver, 0.5).until(ec.alert_is_present())
                alert = driver.switch_to.alert
                message = alert.text
                alert.accept()

                # Parse the alert message
                import json
                data = json.loads(message)

                if data['method'] == 'setVaultSharedKeys':
                    shared_key = get_fmdn_shared_key(data['vaultKeys'])
                    print("[SharedKeyFlow] Received Shared Key.")
                    driver.quit()
                    return shared_key.hex()
                elif data['method'] == 'closeView':
                    print("[SharedKeyFlow] closeView() called. Closing browser.")
                    driver.quit()
                    break

            except Exception:
                pass

    except Exception as e:
        import traceback
        print(f"An error occurred: {type(e).__name__}: {e}")
        try:
            print(f"URL at failure: {driver.current_url}")
        except Exception:
            pass
        traceback.print_exc()
    finally:
        driver.quit()


if __name__ == "__main__":
   request_shared_key_flow()
