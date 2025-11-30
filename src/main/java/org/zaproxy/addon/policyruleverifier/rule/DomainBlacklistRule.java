package org.zaproxy.addon.policyruleverifier.rule;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import org.zaproxy.addon.policyruleverifier.model.HttpMessageView;
import org.zaproxy.addon.policyruleverifier.model.PolicyViolation;

public class DomainBlacklistRule implements PolicyRule{

    private static final List<String> DEFAULT_BLOCKED_DOMAINS =
            List.of(
                    "login.example.com",
                    "tracking.example.com",
                    "ads.example.net",
                    "accounts.google.com",
                    "login.microsoftonline.com",
                    "facebook.com",
                    "google-analytics.com",
                    "doubleclick.net",
                    "adservice.google.com");

    private final String policyName;
    private final List<String> blockedDomains;

    public DomainBlacklistRule() {
        this("DomainBlacklistRule");
    }

    public DomainBlacklistRule(String policyName) {
        this(policyName, DEFAULT_BLOCKED_DOMAINS);
    }

    public DomainBlacklistRule(String policyName, List<String> blockedDomains) {
        this.policyName = policyName;

        List<String> source = blockedDomains;
        if (source == null || source.isEmpty()) {
            source = DEFAULT_BLOCKED_DOMAINS;
        }

        this.blockedDomains =
                source.stream()
                        .filter(Objects::nonNull)
                        .map(d -> d.toLowerCase(Locale.ROOT))
                        .toList();
    }

    @Override
    public String id() {
        return "Policy_" + policyName + ".blockedDomains";
    }

    @Override
    public String displayName() {
        return "Blocked domains";
    }

    @Override
    public Optional<PolicyViolation> apply(HttpMessageView msg, Instant seenAt) {
        URI uri = msg.uri();
        if (uri == null) {
            return Optional.empty();
        }

        String host = uri.getHost();
        if (host == null) {
            return Optional.empty();
        }

        String hostLc = host.toLowerCase(Locale.ROOT);
        String matched =
                blockedDomains.stream()
                        .filter(d -> hostLc.equals(d) || hostLc.endsWith("." + d))
                        .findFirst()
                        .orElse(null);

        if (matched == null) {
            return Optional.empty();
        }

        String details = "Request to blocked domain '" + matched + "': " + uri;

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

}
