"""Work out how serious a finding is.

Two facts decide it, and only two:

    who can see it   public, or behind a login the operator declared
    where it sits    a page, a URL, hidden code, a stylesheet, a third party

The rule from the rulebook is: take the worse of the two. A name and a diagnosis
in a URL on a public page is Critical because public beats URL; the same thing
behind a login is High because the URL still raises it above plain authenticated
access.

The AI is not consulted here. A level that changes between runs is not a level.

Audience is an input, not a guess. Static collection cannot tell whether a page
needs a login, so the operator declares the authenticated paths.

Two refinements, both found by comparing against the answer key at gate G4:

  * Browser storage is not "anyone". It sits in one person's browser, so it is
    treated as authenticated for severity even when the page is public.
  * When a record's health context comes from the file around it rather than
    from the record itself (a name in the metadata of a lab report), the level
    is capped at High. The metadata field does not itself say anything clinical.
"""

from __future__ import annotations

# Worst first. Lower index is worse.
ORDER = ("critical", "high", "medium", "review")

# Carriers that are not visible on the page, so they are never a low grade.
HIGH_CARRIERS = {
    "url", "title", "hidden_code", "css_hidden", "browser_storage",
    "print_css", "html_attribute", "meta_tag", "inline_script",
}

# Carriers where the data has left the organisation, or is offered to strangers.
WITHHOLD_CARRIERS = {"third_party", "sitemap", "robots_txt"}

# Carriers whose audience is one person's device, not the open internet.
CLIENT_SIDE = {"browser_storage"}


def audience(path: str, auth_prefixes: tuple[str, ...]) -> str:
    """Public unless the operator has declared this path as authenticated."""
    for prefix in auth_prefixes:
        if prefix and prefix in path:
            return "authenticated"
    return "public"


def worse(first: str, second: str) -> str:
    return first if ORDER.index(first) <= ORDER.index(second) else second


def decide(carrier: str, ids: dict, has_health: bool, aud: str,
           health_from_context: bool = False) -> str:
    """Return exactly one level. No AI, no randomness, same input same answer."""
    if carrier in WITHHOLD_CARRIERS:
        carrier_level = "critical"
    elif carrier in HIGH_CARRIERS:
        carrier_level = "high"
    else:
        carrier_level = "medium"

    effective_audience = "authenticated" if carrier in CLIENT_SIDE else aud

    if ids.get("always"):
        # A Social Security number, record number, or insurance ID is the worst
        # thing that can be exposed, wherever it is.
        identity_level = "critical" if effective_audience == "public" else "high"
    elif ids.get("strong") and has_health:
        identity_level = "critical" if effective_audience == "public" else "high"
    elif ids.get("identity"):
        identity_level = "medium"
    else:
        identity_level = "review"

    if health_from_context and identity_level == "critical":
        identity_level = "high"

    return worse(carrier_level, identity_level)
