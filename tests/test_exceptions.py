# Tests for src/saprfclib/exceptions.py — the saprfclib-native typed exception hierarchy.
#
# Field set mirrors RFC_ERROR_INFO from sapnwrfc.h (key, message, abapMsgClass,
# abapMsgType, abapMsgNumber, abapMsgV1..V4). See plan 04-04 decisions D-14..D-19.
import pytest

import saprfclib
from saprfclib.exceptions import (
    AbapApplicationError,
    AbapSystemFailure,
    CommunicationError,
    SapRfcError,
)


class TestAbapApplicationError:
    def test_exposes_all_fields(self):
        # Test 1: full field parity with pyrfc (D-15). Unset msg_v2/v3/v4 -> None.
        err = AbapApplicationError(
            key="COMMUNICATION_FAILURE",
            message="something failed",
            msg_class="SY",
            msg_type="E",
            msg_number="002",
            msg_v1="x",
        )
        assert err.key == "COMMUNICATION_FAILURE"
        assert err.message == "something failed"
        assert err.msg_class == "SY"
        assert err.msg_type == "E"
        assert err.msg_number == "002"
        assert err.msg_v1 == "x"
        assert err.msg_v2 is None
        assert err.msg_v3 is None
        assert err.msg_v4 is None

    def test_all_fields_default_to_none(self):
        err = AbapApplicationError()
        for attr in (
            "key",
            "msg_class",
            "msg_type",
            "msg_number",
            "msg_v1",
            "msg_v2",
            "msg_v3",
            "msg_v4",
            "message",
        ):
            assert getattr(err, attr) is None, f"{attr} should default to None"

    def test_str_includes_key_and_message(self):
        # Test 5: a useful diagnostic repr includes both key and message.
        err = AbapApplicationError(key="FOO_BAR", message="boom")
        text = str(err)
        assert "FOO_BAR" in text
        assert "boom" in text


class TestAbapSystemFailure:
    def test_exposes_message(self):
        # Test 2
        err = AbapSystemFailure(message="dump text")
        assert err.message == "dump text"

    def test_message_defaults_to_none(self):
        assert AbapSystemFailure().message is None

    def test_rich_fields(self):
        err = AbapSystemFailure(
            msg_class="SY",
            msg_type="E",
            msg_number="999",
            msg_v1="short dump",
            msg_v2="v2",
            msg_v3="v3",
            msg_v4="v4",
            message="System failure detail",
        )
        assert err.msg_class == "SY"
        assert err.msg_type == "E"
        assert err.msg_number == "999"
        assert err.msg_v1 == "short dump"
        assert err.msg_v2 == "v2"
        assert err.msg_v3 == "v3"
        assert err.msg_v4 == "v4"
        assert err.message == "System failure detail"
        assert str(err) == "System failure detail"

    def test_rich_fields_default_to_none(self):
        err = AbapSystemFailure()
        for attr in (
            "msg_class",
            "msg_type",
            "msg_number",
            "msg_v1",
            "msg_v2",
            "msg_v3",
            "msg_v4",
            "message",
        ):
            assert getattr(err, attr) is None


class TestCommunicationError:
    def test_exposes_message_and_original_exception(self):
        # Test 3
        original = OSError("reset")
        err = CommunicationError(message="connection reset", original_exception=original)
        assert err.message == "connection reset"
        assert err.original_exception is original
        assert isinstance(err.original_exception, OSError)

    def test_defaults(self):
        err = CommunicationError()
        assert err.message is None
        assert err.original_exception is None


class TestHierarchy:
    def test_all_subclass_saprfcerror(self):
        # Test 4
        assert issubclass(AbapApplicationError, SapRfcError)
        assert issubclass(AbapSystemFailure, SapRfcError)
        assert issubclass(CommunicationError, SapRfcError)

    def test_saprfcerror_subclasses_exception(self):
        assert issubclass(SapRfcError, Exception)

    def test_instances_are_saprfcerror(self):
        assert isinstance(AbapApplicationError(), SapRfcError)
        assert isinstance(AbapSystemFailure(), SapRfcError)
        assert isinstance(CommunicationError(), SapRfcError)

    def test_caught_by_common_base(self):
        # A developer can catch any of the three via except SapRfcError (D-18).
        for exc in (AbapApplicationError, AbapSystemFailure, CommunicationError):
            with pytest.raises(SapRfcError):
                raise exc()


class TestTopLevelReExport:
    def test_names_importable_from_package(self):
        # D-18: `from saprfclib import AbapApplicationError` works.
        from saprfclib import (  # noqa: F401
            AbapApplicationError as TopApp,
        )

    def test_top_level_names_are_identical_objects(self):
        assert saprfclib.SapRfcError is SapRfcError
        assert saprfclib.AbapApplicationError is AbapApplicationError
        assert saprfclib.AbapSystemFailure is AbapSystemFailure
        assert saprfclib.CommunicationError is CommunicationError

    def test_names_in_dunder_all(self):
        for name in (
            "SapRfcError",
            "AbapApplicationError",
            "AbapSystemFailure",
            "CommunicationError",
        ):
            assert name in saprfclib.__all__
