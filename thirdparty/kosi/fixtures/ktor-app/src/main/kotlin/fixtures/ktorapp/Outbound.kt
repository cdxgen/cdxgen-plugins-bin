// Outbound half: one literal URL, one config-resolved URL, one env URL and
// one config-resolved TEMPLATE, through java.net.URL so the outbound
// detector's pack shapes match. The config table comes from
// src/main/resources/application.yml.
// kosi:want service protocol=https name=~literal.example.com resolution=literal mode=resolved
// kosi:want service protocol=https name=~api.ktorapp.example.com resolution=config mode=resolved
// kosi:want service name=~KOSI_FIXTURE_API_BASE resolution=env mode=resolved
// kosi:want service protocol=https name=~webhook.example.com resolution=config mode=resolved
// kosi:want-not service protocol=https name=~not-in-config.example.com mode=resolved
package fixtures.ktorapp

import java.net.URL
import java.util.Properties

fun literalUrl(): URL = URL("https://literal.example.com/x")

fun configUrl(props: Properties): URL = URL(props.getProperty("ktorapp.api.base"))

fun envUrl(): URL = URL(System.getenv("KOSI_FIXTURE_API_BASE"))

fun templatedUrl(props: Properties): URL = URL(props.getProperty("ktorapp.webhook"))
