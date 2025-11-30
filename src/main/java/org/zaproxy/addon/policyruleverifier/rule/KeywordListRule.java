package org.zaproxy.addon.policyruleverifier.rule;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import org.zaproxy.addon.policyruleverifier.model.HttpMessageView;
import org.zaproxy.addon.policyruleverifier.model.PolicyViolation;

public class KeywordListRule implements PolicyRule{

    private final String policyName;
    private final List<String> keywords;

    private static final List<String> DEFAULT_KEYWORDS =
            List.of("password", "creditcard", "ssn", "token");

    public KeywordListRule() {
        this("KeywordListRule");
    }

    public KeywordListRule(String policyName) {
        this(policyName, DEFAULT_KEYWORDS);
    }

    public KeywordListRule(String policyName, List<String> keywords) {
        this.policyName = policyName;

        List<String> source = keywords;
        if (source == null || source.isEmpty()) {
            source = DEFAULT_KEYWORDS;
        }

        this.keywords =
                source.stream()
                        .map(k -> k.toLowerCase(Locale.ROOT))
                        .toList();
    }

    @Override
    public String id() {
        return "Policy_" + policyName + ".keywords";
    }

    @Override
    public String displayName() {
        return "Keyword list";
    }

    @Override
    public Optional<PolicyViolation> apply(HttpMessageView msg, Instant seenAt) {
        URI uri = msg.uri();
        String uriText =
                uri != null ? uri.toString().toLowerCase(Locale.ROOT) : "";

        String body = msg.requestBody();
        String bodyText =
                body != null ? body.toLowerCase(Locale.ROOT) : "";

        String matched = null;
        for (String kw : keywords) {
            if (uriText.contains(kw) || bodyText.contains(kw)) {
                matched = kw;
                break;
            }
        }

        if (matched == null) {
            return Optional.empty();
        }

        String details =
                "Request contains keyword '" + matched + "' in URL or request body.";

        PolicyViolation violation =
                new PolicyViolation(
                        policyName,
                        id(),
                        displayName(),
                        msg.method(),
                        uri != null ? uri.toString() : "",
                        seenAt,
                        details);

        return Optional.of(violation);
    }
}
