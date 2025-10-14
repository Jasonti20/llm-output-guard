from llm_output_guard.detectors.pii import find_ssn_spans

def _texts(spans): return [s for (_,_,s) in spans]

def test_ssn_valid_dashed():
    spans = find_ssn_spans("SSN 123-45-6789 here.")
    assert _texts(spans) == ["123-45-6789"]

def test_ssn_valid_nodash():
    spans = find_ssn_spans("EmployeeID: 123456789.")
    assert _texts(spans) == ["123456789"]

def test_ssn_invalid_areas():
    assert _texts(find_ssn_spans("000-12-3456")) == []
    assert _texts(find_ssn_spans("666-12-3456")) == []
    assert _texts(find_ssn_spans("900-12-3456")) == []

def test_ssn_invalid_group_or_serial():
    assert _texts(find_ssn_spans("123-00-6789")) == []
    assert _texts(find_ssn_spans("123-45-0000")) == []

def test_ssn_boundary_guards():
    # should not match inside longer digit strings
    assert _texts(find_ssn_spans("xx1234567890yy")) == []
    assert _texts(find_ssn_spans("a123-45-6789b")) == ["123-45-6789"]
