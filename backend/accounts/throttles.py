from rest_framework.throttling import SimpleRateThrottle


class LoginIPThrottle(SimpleRateThrottle):
    scope = "login_ip"

    def get_cache_key(self, request, view):
        ip = self.get_ident(request)

        return self.cache_format % {
            "scope": self.scope,
            "ident": ip,
        }


class LoginUsernameThrottle(SimpleRateThrottle):
    scope = "login_username"

    def get_cache_key(self, request, view):
        username = request.data.get(
            "username",
            ""
        )

        username = (
            str(username)
            .strip()
            .lower()
        )

        if not username:
            return None

        return self.cache_format % {
            "scope": self.scope,
            "ident": username,
        }


class LoginIPUsernameThrottle(SimpleRateThrottle):
    scope = "login_ip_username"

    def get_cache_key(self, request, view):
        ip = self.get_ident(request)

        username = request.data.get(
            "username",
            ""
        )

        username = (
            str(username)
            .strip()
            .lower()
        )

        if not username:
            return None

        ident = f"{ip}:{username}"

        return self.cache_format % {
            "scope": self.scope,
            "ident": ident,
        }