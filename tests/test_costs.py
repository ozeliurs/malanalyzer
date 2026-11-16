import pytest

from malanalyzer.analyzer import report_result
from malanalyzer.app import render_markdown
from malanalyzer.costs import analysis_cost_footer


def step(identifier, cost, **tokens):
    return {
        "type": "step_finish", "sessionID": "test-session",
        "part": {"id": identifier, "cost": cost, "tokens": tokens},
    }


def test_sum_realistic_turn_costs_with_caching_and_duplicate_events():
    # Shape and values from the verified six-turn Large 4 investigation.
    events = [
        step("1", 0.00489638, input=3087, output=167, reasoning=0, cache={"read": 0, "write": 0}),
        step("2", 0.01103494, input=4564, output=1155, reasoning=0, cache={"read": 0, "write": 0}),
        step("3", 0.00982254, input=3553, output=1091, reasoning=0, cache={"read": 3072, "write": 0}),
        step("4", 0.0058994, input=1841, output=598, reasoning=0, cache={"read": 6400, "write": 0}),
        step("5", 0.01886048, input=4642, output=2856, reasoning=0, cache={"read": 4352, "write": 0}),
        step("6", 0.00671826, input=2908, output=361, reasoning=0, cache={"read": 8960, "write": 0}),
    ]
    events.extend([events[0], {"type": "tool_use", "part": {"cost": 999}}])
    footer = analysis_cost_footer(events, "mistral/mistral-large-4")
    assert "**$0.057232 USD**" in footer
    assert "Completed model turns:** 6" in footer
    assert "20,595 input, 6,228 output, 22,784 cache read, 0 cache write" in footer
    assert "mistral/mistral-large-4" in footer
    assert "previous failed attempts" in footer


@pytest.mark.parametrize("cost", [None, True, -1, "not a price", "NaN", "Infinity", {}, []])
def test_missing_or_invalid_pricing_does_not_claim_zero_cost(cost):
    footer = analysis_cost_footer([step("1", cost)], "mistral/test")
    assert "Unavailable" in footer
    assert "$0.000000" not in footer


def test_partial_pricing_is_labeled_and_zero_is_preserved():
    footer = analysis_cost_footer([step("1", 0.1), step("2", None)], "mistral/test")
    assert "At least **$0.100000 USD**" in footer
    assert "partial; pricing available for 1 of 2" in footer
    zero = analysis_cost_footer([step("free", 0)], "mistral/test")
    assert "**$0.000000 USD**" in zero
    assert "Unavailable" not in zero


def test_no_usage_events_and_tiny_prices():
    assert "Unavailable" in analysis_cost_footer([], "mistral/test")
    assert "Less than $0.000001 USD" in analysis_cost_footer([step("tiny", "0.00000001")], "mistral/test")


def test_report_footer_is_at_end_without_changing_listing_metadata():
    body = "# Sample analysis\n\nAn evidence-backed summary.\n\n" + "Observed behavior. " * 15
    footer = analysis_cost_footer([step("1", 0.025, input=100, output=20, reasoning=10)], "mistral/test")
    report = report_result(body, usage_footer=footer)
    assert report.title == "Sample analysis"
    assert report.summary == "An evidence-backed summary."
    assert report.report_markdown == body.strip() + footer
    assert "Reasoning tokens (as reported):** 10" in report.report_markdown
    assert "<h2>Analysis cost</h2>" in render_markdown(report.report_markdown)
    assert "$0.025000 USD" in render_markdown(report.report_markdown)
    # Preserve the full allowed agent report, reserving space for the generated footer.
    long_report = report_result("x" * 150_000, usage_footer=footer)
    assert long_report.report_markdown.startswith("x" * 150_000)
    with pytest.raises(ValueError):
        report_result("too short", usage_footer=footer)
