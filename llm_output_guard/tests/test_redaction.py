from llm_output_guard.core.engine import redact_text


def test_preserve_len_keep_last4():
    src = "Card: 4242 4242 4242 4242."
    # redact the number slice only
    start = src.index("4242")
    end = src.index(".")
    red = redact_text(
        src, [(start, end)], preserve_len=True, keep_last_n=4, mask_char="*"
    )
    # same length inside slice; ends with last 4
    assert red.endswith("4242.")
    assert len(red) == len(src)
    # everything but last 4 in the slice is masked
    visible_tail = red[end - 4 : end]  # "4242"
    assert visible_tail == "4242"


def test_non_preserve_len_collapses():
    src = "Email: alice@realemail.com"
    s = src.index("alice")
    e = len(src)
    red = redact_text(src, [(s, e)], preserve_len=False, keep_last_n=0, mask_char="█")
    assert red == "Email: █"


def test_overlapping_spans_merge():
    src = "123-45-6789"
    # overlapping spans
    red = redact_text(src, [(0, 5), (3, 11)], preserve_len=True, keep_last_n=0)
    assert red == "***********"  # 11 chars fully masked


def test_multiple_spans_right_to_left():
    src = "A 1111-2222 B 3333-4444 C"
    spans = [(2, 11), (14, 23)]  # two card-like blocks
    red = redact_text(src, spans, preserve_len=True, keep_last_n=4)
    # both blocks keep last 4, spacing intact elsewhere
    assert red.count("*****2222") == 1
    assert red.count("*****4444") == 1
    assert red.endswith(" C")


def test_bounds_clamping_no_crash():
    src = "hello"
    red = redact_text(src, [(-5, 2), (1, 50)], preserve_len=True)
    assert len(red) == len(src)
