from llm_output_guard.detectors.pii import luhn_ok


def test_luhn_valid_examples():
    assert luhn_ok("4242 4242 4242 4242")
    assert luhn_ok("4012-8888-8888-1881")
    assert luhn_ok("378282246310005")


def test_luhn_rejects_invalid():
    assert not luhn_ok("1234 5678 9012 3456")
    assert not luhn_ok("1111 1111 1111 1111")
    assert not luhn_ok("9999999999999999")


def test_luhn_ignores_formatting():
    assert luhn_ok("4 2 4 2-4242-4242 4242")
    assert not luhn_ok("abcd4242efgh")  # too short after digit strip


def test_luhn_length_guard():
    assert not luhn_ok("42424242")  # 8 digits
    assert not luhn_ok("4" * 20)  # 20 digits
