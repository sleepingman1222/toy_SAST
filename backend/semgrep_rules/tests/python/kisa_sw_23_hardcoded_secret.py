password = "hardcoded-password"  # ruleid: kisa.sw23.python.hardcoded-sensitive-value

import os
safe_password = os.environ.get("APP_PASSWORD")  # ok: kisa.sw23.python.hardcoded-sensitive-value
