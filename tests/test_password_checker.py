from unittest.mock import Mock, patch

import pytest

import password_checker as pc


# --- scoring --------------------------------------------------------------

def test_short_password_gets_no_length_points():
    points, feedback = pc.score_length("abc")
    assert points == 0
    assert feedback  # some advice was given


def test_long_password_gets_full_length_points():
    assert pc.score_length("x" * 20)[0] == 40


def test_variety_counts_each_character_class():
    assert pc.score_variety("abc")[0] == 10
    assert pc.score_variety("aB3!")[0] == 40


@pytest.mark.parametrize("password", ["aaa111", "abc", "9876", "qwerty", "1999"])
def test_patterns_are_penalised(password):
    penalty, _ = pc.find_patterns(password)
    assert penalty > 0


def test_common_password_is_weak():
    score, _ = pc.score_password("password")
    assert pc.rating(score) == "Weak"


def test_random_looking_password_is_very_strong():
    score, feedback = pc.score_password("t7#Vq!mZp2@rLw9x")
    assert score == 100
    assert feedback == []


# --- breach check (network is mocked, so tests run offline) ---------------

def fake_response(text):
    response = Mock()
    response.text = text
    response.raise_for_status = Mock()
    return response


def test_sha1_matches_known_value():
    # Known SHA-1 of "password"
    assert pc.sha1_hex("password") == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_only_hash_prefix_is_sent():
    secret = "hunter2-correct-horse"
    with patch.object(pc.requests, "get", return_value=fake_response("")) as get:
        pc.pwned_count(secret)
    url = get.call_args.args[0]
    sent = url.removeprefix(pc.HIBP_RANGE_URL)
    assert sent == pc.sha1_hex(secret)[:5]  # exactly the 5-character prefix
    assert secret not in url


def test_pwned_count_finds_matching_suffix():
    body = (
        "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n"
        "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n"
    )
    with patch.object(pc.requests, "get", return_value=fake_response(body)):
        assert pc.pwned_count("password") == 3861493


def test_pwned_count_returns_zero_when_not_found():
    body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n"
    with patch.object(pc.requests, "get", return_value=fake_response(body)):
        assert pc.pwned_count("password") == 0
