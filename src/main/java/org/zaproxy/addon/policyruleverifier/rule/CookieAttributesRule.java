package org.zaproxy.addon.policyruleverifier.rule;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.zaproxy.addon.policyruleverifier.model.HttpMessageView;
import org.zaproxy.addon.policyruleverifier.model.PolicyViolation;

public class CookieAttributesRule implements PolicyRule {

    @Override
    public String id() {
        return "cookie-attributes";
    }

    @Override
    public String displayName() {
        return "Cookies must have HttpOnly, Secure, and SameSite";
    }

    @Override
    public Optional<PolicyViolation> apply(HttpMessageView msg, Instant seenAt) {

        Map<String, List<String>> responseHeaders = msg.responseHeaders();

        // Look for Set-Cookie header
        List<String> setCookies = responseHeaders.get("Set-Cookie");
        if (setCookies == null || setCookies.isEmpty()) {
            return Optional.empty();
        }

        for (String cookie : setCookies) {
            String lc = cookie.toLowerCase();

            boolean httpOnly = lc.contains("httponly");
            boolean secure = lc.contains("secure");
            boolean sameSite = lc.contains("samesite=");

            if (!httpOnly || !secure || !sameSite) {
                PolicyViolation violation = new PolicyViolation(
                        "Cookie policy",
                        id(),
                        displayName(),
                        msg.method(),
                        msg.uri().toString(),
                        seenAt,
                        "Cookie missing attributes: " + cookie
                );
                return Optional.of(violation);
            }
        }

        return Optional.empty();
    }
}
