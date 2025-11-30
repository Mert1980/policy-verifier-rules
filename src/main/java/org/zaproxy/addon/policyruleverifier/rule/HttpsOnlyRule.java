package org.zaproxy.addon.policyruleverifier.rule;

import java.net.URI;
import java.time.Instant;
import java.util.Optional;
import org.zaproxy.addon.policyruleverifier.model.HttpMessageView;
import org.zaproxy.addon.policyruleverifier.model.PolicyViolation;

public class HttpsOnlyRule implements PolicyRule {

    private final String policyName;

    public HttpsOnlyRule() {
        this("HttpsOnlyRule");
    }

    public HttpsOnlyRule(String policyName) {
        this.policyName = policyName;
    }

    @Override
    public String id() {
        return "Policy_" + policyName + ".httpsOnly";
    }

    @Override
    public String displayName() {
        return "HTTPS only";
    }

    @Override
    public Optional<PolicyViolation> apply(HttpMessageView msg, Instant seenAt) {
        URI uri = msg.uri();
        if (uri == null) {
            return Optional.empty();
        }

        String scheme = uri.getScheme();
        if (!"https".equalsIgnoreCase(scheme)) {
            String details =
                    "Request to non-HTTPS URL: " + uri;

            PolicyViolation violation =
                    new PolicyViolation(
                            policyName,
                            id(),
                            displayName(),
                            msg.method(),
                            uri.toString(),
                            seenAt,
                            details);

            return Optional.of(violation);
        }

        return Optional.empty();
    }
}
