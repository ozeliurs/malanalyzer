from decimal import Decimal, InvalidOperation


def analysis_cost_footer(events: list[dict], model: str) -> str:
    """Sum completed-turn estimates from OpenCode; missing prices are never treated as free."""
    seen = set()
    turns = priced_turns = 0
    cost = Decimal("0")
    counts = dict.fromkeys(("input", "output", "reasoning", "cache_read", "cache_write"), 0)
    has_tokens = False
    for event in events:
        if event.get("type") not in ("step_finish", "step-finish"):
            continue
        part = event.get("part")
        if not isinstance(part, dict):
            continue
        identity = part.get("id") or part.get("messageID")
        if identity:
            key = (event.get("sessionID") or part.get("sessionID"), identity)
            if key in seen:
                continue
            seen.add(key)
        turns += 1
        value = part.get("cost")
        if not isinstance(value, bool) and isinstance(value, (int, float, str)):
            try:
                amount = Decimal(str(value))
                if amount.is_finite() and amount >= 0:
                    cost += amount
                    priced_turns += 1
            except InvalidOperation:
                pass
        tokens = part.get("tokens")
        if isinstance(tokens, dict):
            cache = tokens.get("cache")
            cache = cache if isinstance(cache, dict) else {}
            values = {
                "input": tokens.get("input"), "output": tokens.get("output"),
                "reasoning": tokens.get("reasoning"),
                "cache_read": cache.get("read"), "cache_write": cache.get("write"),
            }
            for name, count in values.items():
                if type(count) is int and count >= 0:
                    counts[name] += count
                    has_tokens = True

    if not priced_turns:
        price = "Unavailable — OpenCode did not report a cost estimate."
    elif priced_turns != turns:
        price = f"At least **${cost:,.6f} USD** (partial; pricing available for {priced_turns} of {turns} completed turns)."
    elif cost and cost < Decimal("0.000001"):
        price = "**Less than $0.000001 USD**"
    else:
        price = f"**${cost:,.6f} USD**"
    lines = [
        "", "", "---", "", "## Analysis cost", "",
        f"- **Estimated model API cost:** {price}",
        f"- **Model:** `{model}`",
        f"- **Completed model turns:** {turns:,}",
    ]
    if has_tokens:
        lines.append(
            f"- **Token usage (as reported):** {counts['input']:,} input, {counts['output']:,} output, "
            f"{counts['cache_read']:,} cache read, {counts['cache_write']:,} cache write."
        )
        if counts["reasoning"]:
            lines.append(f"- **Reasoning tokens (as reported):** {counts['reasoning']:,}")
    lines.extend([
        "", "Estimate from OpenCode's per-turn model pricing for this analysis session. "
        "Excludes infrastructure costs and any previous failed attempts; the provider's invoice may differ.",
    ])
    return "\n".join(lines)
