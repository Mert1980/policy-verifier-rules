package org.zaproxy.addon.policyruleverifier.rule;

import java.time.Instant;
import java.util.Optional;
import java.util.regex.Pattern;
import org.zaproxy.addon.policyruleverifier.model.HttpMessageView;
import org.zaproxy.addon.policyruleverifier.model.PolicyViolation;

public class EmailDetectionRule implements PolicyRule {

    private static final Pattern EMAIL_REGEX =
            Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}",
                    Pattern.CASE_INSENSITIVE);

    @Override
    public String id() {
        return "email-detection";
    }

    @Override
    public String displayName() {
        return "Request contains an email address";
    }

    @Override
    public Optional<PolicyViolation> apply(HttpMessageView msg, Instant seenAt) {

        // 1. Check URL
        String url = msg.uri().toString();
        if (EMAIL_REGEX.matcher(url).find()) {
            return Optional.of(createViolation(msg, seenAt, "Email detected in request URL."));
        }

        // 2. Check request body
        String requestBody = msg.requestBody();
        if (requestBody != null && EMAIL_REGEX.matcher(requestBody).find()) {
            return Optional.of(createViolation(msg, seenAt, "Email detected in request body."));
        }

        // 3. ✅ Check **RESPONSE BODY** (where your <p> emails live)
        String responseBody = msg.responseBody();
        if (responseBody != null && EMAIL_REGEX.matcher(responseBody).find()) {
            return Optional.of(createViolation(msg, seenAt, "Email detected in response body."));
        }
        return Optional.empty();
    }


    private PolicyViolation createViolation(HttpMessageView msg, Instant at, String details) {
        return new PolicyViolation(
                /* policyName */ "Email detected policy",
                /* ruleId     */ id(),
                /* ruleName   */ displayName(),
                /* method     */ msg.method(),
                /* uri        */ msg.uri().toString(),
                /* timestamp  */ at,
                /* details    */ details
        );
    }

}
